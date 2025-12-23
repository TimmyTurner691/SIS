import time
import json
import redis
import os
import re
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime
from collections import deque
from elasticsearch import Elasticsearch
from utils_alert import send_email_alert

# ================= CONFIGURACIÓN =================
REDIS_HOST = 'redis'
ELASTIC_HOST = 'http://elasticsearch:9200'
INDEX_NAME = 'sis-logs-v1'
CVE_REPORT_PATH = '/app/cve_report.csv'

LOG_FILES = {
    'snort': '/var/log/snort/alert',
    'zeek_conn': '/var/log/zeek/conn.log',
    'zeek_iec104': '/var/log/zeek/iec104.log'
}

IA_WINDOW_SIZE = 200
IA_CONTAMINATION = 0.05

# ================= CLASES DE CORRELACIÓN =================

class MitreICSCorrelator:
    def __init__(self):
        self.state_db = {} 
        self.mitre_rules = {
            'discovery': {'id': 'T0846', 'tactic': 'Discovery', 'name': 'Network Scan'},
            'c2_ot':     {'id': 'T0869', 'tactic': 'Command and Control', 'name': 'Standard Protocol (OT)'},
            'exploit':   {'id': 'T0883', 'tactic': 'Execution', 'name': 'Exploitation'},
            'impact':    {'id': 'T0814', 'tactic': 'Impact', 'name': 'DoS / Process Impact'},
            'lateral':   {'id': 'T0866', 'tactic': 'Lateral Movement', 'name': 'Remote Services'}
        }

    def procesar_evento(self, ip_atacante, log_json):
        if ip_atacante not in self.state_db:
            self.state_db[ip_atacante] = {'techniques': set(), 'tactics': set()}
        
        perfil = self.state_db[ip_atacante]
        detected = []

        # A. Análisis SNORT
        if log_json.get('source') == 'snort':
            msg = log_json.get('message', '').lower()
            if 'dos' in msg or 'flood' in msg: detected.append(self.mitre_rules['impact'])
            elif 'exploit' in msg: detected.append(self.mitre_rules['exploit'])
            else: detected.append(self.mitre_rules['discovery']) 
        
        # B. Análisis ZEEK (OT)
        else:
            # Normalizamos puerto a string para comparar
            dst_port = str(log_json.get('dst_port', ''))
            proto = str(log_json.get('protocol', '')).lower()
            
            # Detección de Protocolos Industriales (C2 / Ingress)
            if 'iec104' in proto or dst_port in ['2404', '502', '102', '44818']:
                detected.append(self.mitre_rules['c2_ot'])
            
            # Escaneo (Discovery) - Solo si la IA también ve anomalía
            if log_json.get('ai_score', 0) < -0.6: 
                 detected.append(self.mitre_rules['discovery'])

        # Actualizar Memoria
        for rule in detected:
            perfil['techniques'].add(rule['id'])
            perfil['tactics'].add(rule['tactic'])

        # Calcular Kill Chain (Estado actual)
        tactics = perfil['tactics']
        risk = 1
        msg = "Info"

        if 'Impact' in tactics:
            risk = 25; msg = "CRÍTICO: Impacto en Proceso (T0814)"
        elif 'Execution' in tactics or 'Lateral Movement' in tactics:
            risk = 20; msg = "ALTO: Ejecución / Lateralidad"
        elif 'Command and Control' in tactics and 'Discovery' in tactics:
            risk = 18; msg = "ALERTA: Kill Chain Avanzada"
        elif 'Command and Control' in tactics:
            risk = 10; msg = "MEDIO: Acceso a Protocolo OT"
        elif 'Discovery' in tactics:
            risk = 5; msg = "BAJO: Reconocimiento"

        return {
            "mitre_score": risk,
            "mitre_msg": msg,
            "mitre_tactics": list(tactics),
            "mitre_techniques": list(perfil['techniques'])
        }

class RiskFusionEngine:
    def __init__(self, mitre_engine):
        self.mitre = mitre_engine
        self.cve_db = pd.DataFrame()
        self.cargar_cves()

    def cargar_cves(self):
        if os.path.exists(CVE_REPORT_PATH):
            try:
                self.cve_db = pd.read_csv(CVE_REPORT_PATH)
                if 'ip' in self.cve_db.columns:
                    self.cve_db['ip'] = self.cve_db['ip'].astype(str)
            except: 
                print("⚠️ No se pudo cargar BD de CVEs", flush=True)

    def obtener_impacto_activo(self, ip_destino):
        # Si no hay DB o la IP es genérica, retorno impacto bajo
        if self.cve_db.empty or ip_destino == "0.0.0.0":
            return 2 
        
        # Búsqueda flexible (por IP exacta o si la IP está en el nombre del dispositivo)
        vulns = self.cve_db[
            (self.cve_db.get('ip') == str(ip_destino)) | 
            (self.cve_db['device'].astype(str).str.contains(str(ip_destino), na=False))
        ]
        
        if not vulns.empty:
            severities = vulns['severity'].str.upper().tolist()
            if 'CRITICAL' in severities: return 5
            if 'HIGH' in severities: return 4
            if 'MEDIUM' in severities: return 3
        return 2

    def evaluar(self, doc, ml_anomaly_score):
        # 1. Probabilidad (IA + MITRE)
        mitre_data = self.mitre.procesar_evento(doc.get('src_ip'), doc)
        
        # Score IA (-1 a 0, donde menor es más anómalo)
        ia_risk = 1
        if ml_anomaly_score < -0.7: ia_risk = 5
        elif ml_anomaly_score < -0.6: ia_risk = 4
        elif ml_anomaly_score < -0.5: ia_risk = 3
        
        # Score MITRE
        mitre_risk = 1
        m_score = mitre_data['mitre_score']
        if m_score >= 25: mitre_risk = 5
        elif m_score >= 18: mitre_risk = 4
        elif m_score >= 10: mitre_risk = 3
        
        probabilidad = max(ia_risk, mitre_risk)

        # 2. Impacto (Vulnerabilidad del Activo)
        impacto = self.obtener_impacto_activo(doc.get('dst_ip'))

        # 3. Fusión
        total_score = probabilidad * impacto
        
        label = "BAJO"
        if total_score >= 17: label = "CRÍTICO"
        elif total_score >= 8: label = "MEDIO"

        doc.update({
            "risk_total_score": total_score,
            "risk_label": label,
            "risk_probability": probabilidad,
            "risk_impact": impacto,
            "mitre_tactics": mitre_data['mitre_tactics'],
            "mitre_techniques": mitre_data['mitre_techniques'],
            "mitre_msg": mitre_data['mitre_msg']
        })
        return doc, total_score

# ================= PARSERS (AQUÍ ESTÁ LA CORRECCIÓN) =================
def connect_services():
    r = None; es = None
    while not r:
        try:
            r = redis.Redis(host=REDIS_HOST, port=6379, db=0, decode_responses=True); r.ping()
            print("✅ Redis OK", flush=True)
        except: time.sleep(2)
    while not es:
        try:
            es = Elasticsearch([ELASTIC_HOST]); es.ping()
            print("✅ Elastic OK", flush=True)
        except: time.sleep(5)
    return r, es

def parse_snort(line):
    try:
        msg = re.search(r'\[\*\*\] (.*?) \[\*\*\]', line)
        ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
        return {
            "source": "snort", "event_type": "alert",
            "message": msg.group(1) if msg else "Alert",
            "src_ip": ips[0] if len(ips)>0 else "0.0.0.0",
            "dst_ip": ips[1] if len(ips)>1 else "0.0.0.0",
            "raw_log": line.strip()
        }
    except: return None

def parse_zeek(line, log_type):
    """
    Parser robusto: Intenta JSON primero, si falla, intenta TSV (Tablas).
    Esto arregla la lectura de logs de Zeek que no sean JSON.
    """
    if not line or line.startswith('#'): return None
    doc = {}
    
    # INTENTO 1: JSON
    try:
        data = json.loads(line)
        doc = {
            "source": "zeek", 
            "sub_source": log_type,
            "src_ip": data.get('id.orig_h') or data.get('id', {}).get('orig_h', "0.0.0.0"),
            "dst_ip": data.get('id.resp_h') or data.get('id', {}).get('resp_h', "0.0.0.0"),
            "dst_port": data.get('id.resp_p') or data.get('id', {}).get('resp_p', 0),
            "protocol": data.get('proto', 'tcp'),
            "raw_log": str(data)[:500]
        }
        if log_type == 'zeek_iec104' or 'iec104' in line:
            doc['protocol'] = 'iec104'
        return doc
    except json.JSONDecodeError:
        pass # Fallo JSON, seguimos a TSV

    # INTENTO 2: TSV (Tab Separated Values) - Estándar Zeek
    try:
        parts = line.split('\t')
        if len(parts) < 6: return None # Demasiado corta
        
        # Mapeo aproximado de conn.log estándar:
        # 2: id.orig_h, 4: id.resp_h, 5: id.resp_p, 6: proto
        doc = {
            "source": "zeek",
            "sub_source": log_type,
            "src_ip": parts[2],
            "dst_ip": parts[4],
            "dst_port": parts[5],
            "protocol": parts[6] if len(parts) > 6 else "unknown",
            "raw_log": line[:500]
        }
        
        # Forzar protocolo si viene del log específico de IEC104
        if log_type == 'zeek_iec104':
            doc['protocol'] = 'iec104'
            
        return doc
    except Exception as e:
        return None

# ================= MAIN LOOP =================
def main():
    r, es = connect_services()
    
    model = IsolationForest(contamination=IA_CONTAMINATION, n_jobs=-1)
    history = deque(maxlen=IA_WINDOW_SIZE)
    is_trained = False

    mitre_engine = MitreICSCorrelator()
    fusion_engine = RiskFusionEngine(mitre_engine)

    file_pointers = {k: 0 for k in LOG_FILES}
    # Inicializar punteros si archivos existen
    for k, p in LOG_FILES.items():
        if os.path.exists(p): file_pointers[k] = os.path.getsize(p)

    print("🚀 SIS Core: Backend Iniciado y Corregido", flush=True)

    while True:
        time.sleep(1)
        batch_events = []
        stats_snort = 0; stats_total = 0

        # 1. LEER LOGS
        for key, path in LOG_FILES.items():
            if not os.path.exists(path): continue
            
            try:
                current_size = os.path.getsize(path)
                if current_size < file_pointers[key]: file_pointers[key] = 0 # Rotación log
                
                if current_size > file_pointers[key]:
                    with open(path, 'r') as f:
                        f.seek(file_pointers[key])
                        for line in f:
                            doc = parse_snort(line) if key == 'snort' else parse_zeek(line, key)
                            if doc:
                                doc['@timestamp'] = datetime.now().isoformat()
                                batch_events.append(doc)
                                if key == 'snort': stats_snort += 1
                                stats_total += 1
                    file_pointers[key] = current_size
                    
                    # Debug print para verificar que lee Zeek
                    if key != 'snort' and stats_total > 0:
                        print(f"📡 Zeek data: {stats_total} eventos leídos.", flush=True)

            except Exception as e:
                print(f"Error leyendo {path}: {e}", flush=True)

        # 2. IA
        anomaly_score = 0.5 
        if stats_total > 0:
            history.append([stats_snort, stats_total])
            if len(history) >= 20:
                if not is_trained:
                    model.fit(list(history)); is_trained = True
                
                features = np.array([[stats_snort, stats_total]])
                pred = model.predict(features)
                if pred[0] == -1:
                    anomaly_score = float(model.decision_function(features)[0])

        # 3. FUSIÓN Y ENRIQUECIMIENTO
        processed_docs = []
        max_risk_batch = 0

        for doc in batch_events:
            doc['ai_score'] = float(anomaly_score)
            doc_enriquecido, risk_val = fusion_engine.evaluar(doc, anomaly_score)
            processed_docs.append(doc_enriquecido)
            if risk_val > max_risk_batch: max_risk_batch = risk_val

        # 4. ALERTA Y GUARDADO
        if max_risk_batch >= 17:
            print(f"🚨 ALERTA CRÍTICA GENERADA (Riesgo: {max_risk_batch})", flush=True)
            send_email_alert(
                "SIS ALERTA: Fusión de Riesgos", 
                f"Detectado incidente crítico (Score: {max_risk_batch}).\nVer Dashboard."
            )

        if processed_docs:
            for d in processed_docs:
                try: es.index(index=INDEX_NAME, document=d)
                except Exception as e: print(f"Error Index: {e}", flush=True)
            
            print(f"📦 Indexados: {len(processed_docs)} logs. Riesgo Max: {max_risk_batch}", flush=True)

if __name__ == "__main__":
    main()