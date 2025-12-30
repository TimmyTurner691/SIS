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

# ================= CONFIGURACIÓN =================
REDIS_HOST = 'redis'
ELASTIC_HOST = 'http://elasticsearch:9200'
INDEX_NAME = 'sis-logs-v1'
CVE_REPORT_PATH = '/app/cve_report.csv'

# Mapeo de archivos de logs
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
            dst_port = str(log_json.get('dst_port', ''))
            proto = str(log_json.get('protocol', '')).lower()
            
            if 'iec104' in proto or dst_port in ['2404', '502', '102', '44818']:
                detected.append(self.mitre_rules['c2_ot'])
            
            if log_json.get('ai_score', 0) < -0.6: 
                 detected.append(self.mitre_rules['discovery'])

        for rule in detected:
            perfil['techniques'].add(rule['id'])
            perfil['tactics'].add(rule['tactic'])

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
            except: pass

    def obtener_impacto_activo(self, ip_destino):
        if self.cve_db.empty or ip_destino == "0.0.0.0": return 2 
        
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
        mitre_data = self.mitre.procesar_evento(doc.get('src_ip'), doc)
        
        ia_risk = 1
        if ml_anomaly_score < -0.7: ia_risk = 5
        elif ml_anomaly_score < -0.6: ia_risk = 4
        elif ml_anomaly_score < -0.5: ia_risk = 3
        
        mitre_risk = 1
        m_score = mitre_data['mitre_score']
        if m_score >= 25: mitre_risk = 5
        elif m_score >= 18: mitre_risk = 4
        elif m_score >= 10: mitre_risk = 3
        
        probabilidad = max(ia_risk, mitre_risk)
        impacto = self.obtener_impacto_activo(doc.get('dst_ip'))
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

# ================= PARSERS =================
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
        if "[**]" not in line: return None
        msg_match = re.search(r'\] (.*?) \[', line)
        msg = msg_match.group(1) if msg_match else "Snort Alert"
        ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
        return {
            "source": "snort", "event_type": "alert",
            "message": msg,
            "src_ip": ips[0] if len(ips)>0 else "0.0.0.0",
            "dst_ip": ips[1] if len(ips)>1 else "0.0.0.0",
            "raw_log": line.strip()
        }
    except: return None

def parse_zeek(line, log_type):
    if not line or line.startswith('#'): return None
    doc = {}
    try:
        data = json.loads(line)
        doc = {
            "source": "zeek", "sub_source": log_type,
            "src_ip": data.get('id.orig_h') or data.get('id', {}).get('orig_h', "0.0.0.0"),
            "dst_ip": data.get('id.resp_h') or data.get('id', {}).get('resp_h', "0.0.0.0"),
            "dst_port": data.get('id.resp_p') or data.get('id', {}).get('resp_p', 0),
            "protocol": data.get('proto', 'tcp'),
            "raw_log": str(data)[:500]
        }
        if log_type == 'zeek_iec104' or 'iec104' in line: doc['protocol'] = 'iec104'
        return doc
    except:
        try:
            parts = line.split('\t')
            if len(parts) < 6: return None
            doc = {
                "source": "zeek", "sub_source": log_type,
                "src_ip": parts[2], "dst_ip": parts[4],
                "dst_port": parts[5], "protocol": parts[6] if len(parts)>6 else "unknown",
                "raw_log": line[:500]
            }
            if log_type == 'zeek_iec104': doc['protocol'] = 'iec104'
            return doc
        except: return None

# ================= MAIN LOOP =================
def main():
    print("🚀 SIS Core: Iniciando Backend...", flush=True)
    r, es = connect_services()
    
    model = IsolationForest(contamination=IA_CONTAMINATION, n_jobs=-1)
    history = deque(maxlen=IA_WINDOW_SIZE)
    is_trained = False

    mitre_engine = MitreICSCorrelator()
    fusion_engine = RiskFusionEngine(mitre_engine)

    # 1. INICIALIZAR PUNTEROS AL FINAL (SEEK END)
    file_pointers = {}
    for k, p in LOG_FILES.items():
        if os.path.exists(p):
            file_pointers[k] = os.path.getsize(p)
        else:
            file_pointers[k] = 0

    print(f"👀 Escuchando nuevos eventos...", flush=True)

    while True:
        time.sleep(1)
        
        for key, path in LOG_FILES.items():
            if not os.path.exists(path): continue
            
            # Verificar si hay cambios reales en el tamaño
            try:
                current_size = os.path.getsize(path)
                
                # Caso rotación de logs (archivo más chico que antes)
                if current_size < file_pointers[key]:
                    file_pointers[key] = 0
                
                # SI HAY DATOS NUEVOS
                if current_size > file_pointers[key]:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(file_pointers[key])
                        lines = f.readlines()
                        
                        # ¡CRUCIAL! Actualizamos el puntero AQUÍ MISMO usando tell()
                        file_pointers[key] = f.tell()

                        # Ahora procesamos las líneas leídas en memoria
                        batch_docs = []
                        stats_snort = 0; stats_total = 0

                        for line in lines:
                            doc = parse_snort(line) if key == 'snort' else parse_zeek(line, key)
                            if doc:
                                doc['@timestamp'] = datetime.now().isoformat()
                                batch_docs.append(doc)
                                if key == 'snort': stats_snort += 1
                                stats_total += 1
                        
                        # --- LÓGICA DE IA Y ENVIO ---
                        anomaly_score = 0.5
                        if stats_total > 0:
                            history.append([stats_snort, stats_total])
                            if len(history) >= 20:
                                if not is_trained:
                                    try: model.fit(list(history)); is_trained = True
                                    except: pass
                                if is_trained:
                                    features = np.array([[stats_snort, stats_total]])
                                    if model.predict(features)[0] == -1:
                                        anomaly_score = float(model.decision_function(features)[0])
                        
                        for doc in batch_docs:
                            doc['ai_score'] = float(anomaly_score)
                            final_doc, risk = fusion_engine.evaluar(doc, anomaly_score)
                            try: es.index(index=INDEX_NAME, document=final_doc)
                            except Exception as e: print(f"Error ES: {e}", flush=True)
                            
                        if batch_docs:
                             print(f"📦 {key.upper()}: Procesados {len(batch_docs)} eventos.", flush=True)

            except Exception as e:
                print(f"⚠️ Error loop principal: {e}", flush=True)

if __name__ == "__main__":
    main()