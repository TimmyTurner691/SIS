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
import warnings
from elasticsearch import ElasticsearchWarning
from utils_alert import send_email_alert 

# Silenciar warnings
warnings.filterwarnings("ignore", category=ElasticsearchWarning)

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
            dst_port = str(log_json.get('dst_port', ''))
            proto = str(log_json.get('protocol', '')).lower()
            
            # Detectar IEC-104 o Modbus
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
        self.cve_path = '/app/cve_report.csv'
        self.inventory = {} 
        self.inventory_path = '/app/ot_inventory.json'
        
        self.cargar_datos()

    def cargar_datos(self):
        # 1. Cargar CVEs (Técnico)
        if os.path.exists(self.cve_path):
            try:
                # Intentamos leer ignorando errores de formato y limpiando espacios
                self.cve_db = pd.read_csv(self.cve_path, skipinitialspace=True)
                
                # Normalizamos nombres de columnas a minúsculas para evitar errores
                self.cve_db.columns = [c.lower().strip() for c in self.cve_db.columns]
                
                print(f"CVE Database cargada. Columnas detectadas: {list(self.cve_db.columns)}", flush=True)
                
                # Asegurar que la columna ip sea string
                if 'ip' in self.cve_db.columns:
                    self.cve_db['ip'] = self.cve_db['ip'].astype(str)
                else:
                    print("ADVERTENCIA: No se encontró la columna 'ip' en cve_report.csv", flush=True)
                    
            except Exception as e:
                print(f"⚠️ Error cargando CVEs: {e}", flush=True)
                self.cve_db = pd.DataFrame() # DataFrame vacío por seguridad

        # 2. Cargar Inventario (Operativo)
        if os.path.exists(self.inventory_path):
            try:
                with open(self.inventory_path, 'r') as f:
                    data = json.load(f)
                    for item in data:
                        self.inventory[item.get('ip')] = item.get('criticality', 'LOW')
                print(f"Inventario Operativo cargado ({len(self.inventory)} activos).", flush=True)
            except: pass

    def get_score_from_label(self, label):
        label = str(label).upper()
        if 'CRITICAL' in label: return 5
        if 'HIGH' in label: return 4
        if 'MEDIUM' in label: return 3
        if 'LOW' in label: return 1
        return 2 

    def calcular_impacto_unificado(self, ip_destino):
        ip_str = str(ip_destino)
        
        # --- FACTOR 1: Importancia Operativa (JSON) ---
        label_ops = self.inventory.get(ip_str, 'UNKNOWN')
        score_importancia_operativa = self.get_score_from_label(label_ops)
        
        # --- FACTOR 2: Vulnerabilidad Técnica (CSV) ---
        score_cve = 1
        
        # VERIFICACIÓN DE SEGURIDAD 
        if not self.cve_db.empty and 'ip' in self.cve_db.columns and 'severity' in self.cve_db.columns:
            try:
                vulns = self.cve_db[self.cve_db['ip'] == ip_str]
                if not vulns.empty:
                    severities = vulns['severity'].apply(self.get_score_from_label)
                    if not severities.empty:
                        score_cve = severities.max()
            except Exception as e:
                # Si falla algo aquí, solo imprimimos y seguimos con score 1
                # No detenemos el loop principal
                pass
        
        # --- IMPACTO FINAL ---
        impacto_final = max(score_importancia_operativa, score_cve)
        
        return impacto_final, score_importancia_operativa, score_cve

    def evaluar(self, doc, ml_anomaly_score):
        mitre_data = self.mitre.procesar_evento(doc.get('src_ip'), doc)
        
        ia_risk = 1
        if ml_anomaly_score < -0.7: ia_risk = 5
        elif ml_anomaly_score < -0.6: ia_risk = 4
        
        mitre_risk = 1
        m_score = mitre_data['mitre_score']
        if m_score >= 25: mitre_risk = 5
        elif m_score >= 18: mitre_risk = 4
        elif m_score >= 10: mitre_risk = 3
        
        probabilidad = max(ia_risk, mitre_risk)
        
        # Calculamos impacto de forma segura
        impacto, score_ops, score_cve = self.calcular_impacto_unificado(doc.get('dst_ip'))
        
        total_score = probabilidad * impacto
        
        label = "BAJO"
        if total_score >= 17: label = "CRÍTICO"
        elif total_score >= 10: label = "MEDIO"

        doc.update({
            "risk_total_score": total_score,
            "risk_label": label,
            "risk_probability": probabilidad,
            "risk_impact": impacto,
            "impact_details": {
                "operational_score": int(score_ops),
                "vulnerability_score": int(score_cve)
            },
            "mitre_msg": mitre_data['mitre_msg'],
            "mitre_tactics": mitre_data['mitre_tactics']
        })
        return doc, total_score
    
# ================= PARSERS INGESTA Y NORMALIZACIÓN =================
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
    print("SIS Core: Iniciando Backend...", flush=True)
    r, es = connect_services() # Conexión a Redis y Elastic
    model = IsolationForest(contamination=IA_CONTAMINATION, n_jobs=-1) # Modelo IA
    history = deque(maxlen=IA_WINDOW_SIZE) # Historial para IA
    is_trained = False # Bandera de entrenamiento IA

    mitre_engine = MitreICSCorrelator() # Motor de correlación MITRE ICS
    fusion_engine = RiskFusionEngine(mitre_engine) # Motor de fusión de riesgos

    # Control de alertas (Anti-Spam de correos)
    # Diccionario: { 'IP_ATACANTE': timestamp_ultima_alerta }
    alert_cooldown = {} 

    file_pointers = {} # Punteros de archivos de log
    for k, p in LOG_FILES.items(): # recorremos los logs para no volver a leer logs antiguos
        if os.path.exists(p):
            file_pointers[k] = os.path.getsize(p)
        else:
            file_pointers[k] = 0

    print(f" Escuchando nuevos eventos...", flush=True)

    while True:
        time.sleep(1)
        
        for key, path in LOG_FILES.items():
            if not os.path.exists(path): continue
            
            try:
                current_size = os.path.getsize(path)
                if current_size < file_pointers[key]:
                    file_pointers[key] = 0
                
                if current_size > file_pointers[key]: 
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(file_pointers[key])
                        lines = f.readlines()
                        file_pointers[key] = f.tell()

                        batch_docs = []
                        stats_snort = 0; stats_total = 0

                        for line in lines:
                            doc = parse_snort(line) if key == 'snort' else parse_zeek(line, key)
                            if doc:
                                doc['@timestamp'] = datetime.now().isoformat()
                                batch_docs.append(doc)
                                if key == 'snort': stats_snort += 1
                                stats_total += 1
                        
                        # --- IA UPDATE ---
                        anomaly_score = 0.5
                        if stats_total > 0:
                            history.append([stats_snort, stats_total])
                            if len(history) >= 20: # Esperamos a tener datos suficientes y entrenar
                                if not is_trained:
                                    try: model.fit(list(history)); is_trained = True
                                    except: pass
                                if is_trained:
                                    features = np.array([[stats_snort, stats_total]])
                                    if model.predict(features)[0] == -1: #  Anomalía detectada
                                        anomaly_score = float(model.decision_function(features)[0]) # puntuación de anomalía
                        
                        # --- PROCESAMIENTO Y ALERTAS ---
                        for doc in batch_docs:
                            doc['ai_score'] = float(anomaly_score) # Añadimos score IA al doc
                            final_doc, risk = fusion_engine.evaluar(doc, anomaly_score) # Evaluación de riesgo

                            # >>> AQUÍ ESTÁ LA LÓGICA DE ALERTA <<<<
                            if final_doc.get('risk_label') == 'CRÍTICO':
                                ip_atacante = final_doc.get('src_ip', 'unknown')
                                now = time.time()
                                
                                # Solo enviar correo si pasaron más de 60 seg desde la última alerta para esta IP
                                last_alert = alert_cooldown.get(ip_atacante, 0)
                                if (now - last_alert) > 60:
                                    asunto = f"{final_doc.get('mitre_msg', 'Ataque Detectado')}"
                                    cuerpo = f"""
                                    ⚠️ ALERTA DE SEGURIDAD INDUSTRIAL CRÍTICA ⚠️
                                    
                                    IP Origen: {ip_atacante}
                                    IP Destino: {final_doc.get('dst_ip')}
                                    Protocolo: {final_doc.get('protocol')}
                                    Riesgo Score: {risk}
                                    Tácticas MITRE: {final_doc.get('mitre_tactics')}
                                    Mensaje: {final_doc.get('mitre_msg')}
                                    
                                    El sistema ha registrado actividad maliciosa de alto impacto.
                                    """
                                    send_email_alert(asunto, cuerpo, level="CRITICAL")
                                    
                                    # Actualizar cooldown
                                    alert_cooldown[ip_atacante] = now

                            try: es.index(index=INDEX_NAME, document=final_doc)
                            except Exception as e: print(f"Error ES: {e}", flush=True)
                            
                        if batch_docs:
                             print(f"📦 {key.upper()}: Procesados {len(batch_docs)} eventos.", flush=True)

            except Exception as e:
                print(f"⚠️ Error loop principal: {e}", flush=True)

if __name__ == "__main__":
    main()