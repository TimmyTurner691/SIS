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

# Dummy import por si falla
try:
    from utils_alert import send_email_alert
except ImportError:
    def send_email_alert(subject, body, level):
        print(f"📧 [EMAIL SIMULADO] {subject}", flush=True)

warnings.filterwarnings("ignore", category=ElasticsearchWarning)

# ================= CONFIGURACIÓN =================
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
ELASTIC_HOST = os.getenv("ELASTIC_HOST", "elasticsearch")
REDIS_KEY = "sis_queue"
INDEX_NAME = 'sis-logs-v1'

IA_WINDOW_SIZE = 200
IA_CONTAMINATION = 0.05

# ================= LÓGICA DE TRADUCCIÓN HUMANA (NUEVO) 🏭 =================
def traducir_iec104(sub_source, raw_log_str):
    """
    Convierte nombres de archivos crípticos de Zeek en descripciones para humanos.
    """
    sub = sub_source.lower()
    raw = raw_log_str.upper()

    # 1. COMANDOS (C_ = Control)
    if 'c_sc' in sub: return "⚙️ Comando Simple (Switch/Breaker)"
    if 'c_dc' in sub: return "⚙️ Comando Doble (Breaker)"
    if 'c_rc' in sub: return "⚙️ Comando de Regulación (Set Point)"
    if 'c_se' in sub: return "⚙️ Comando de Valor (Set Value)"
    if 'c_ic' in sub: return "❓ Interrogación General (Polling)"
    
    # 2. TELEMETRÍA / MONITORIZACIÓN (M_ = Monitor)
    if 'm_me' in sub: return "📈 Telemetría (Medida Analógica)"
    if 'm_sp' in sub: return "🚨 Estado (Single Point)"
    if 'm_dp' in sub: return "🚨 Estado Doble (Double Point)"
    if 'm_it' in sub: return "🔢 Contador Integrado"

    # 3. GESTIÓN DE CONEXIÓN (APCI U-Format)
    if 'apci_u' in sub:
        if 'STARTDT' in raw: return "🔌 Inicio Conexión (STARTDT)"
        if 'STOPDT'  in raw: return "🔌 Fin Conexión (STOPDT)"
        if 'TESTFR'  in raw: return "💓 Test de Enlace (Heartbeat)"
        return "🔌 Gestión de Conexión (U-Format)"

    # 4. CONFIRMACIONES Y SECUENCIA
    if 'apci_s' in sub: return "🛡️ Confirmación de Trama (ACK)"
    if 'apci_i' in sub: return "📡 Trama de Datos (I-Format)"
    
    # 5. METADATOS
    if 'asdu' in sub: return "🆔 Cabecera de Datos (ASDU)"
    
    return "📦 Tráfico IEC-104 Genérico"

# ================= MOTORES DE INTELIGENCIA =================

class MitreICSCorrelator:
    def __init__(self):
        self.mitre_rules = {
            'discovery': {'id': 'T0846', 'tactic': 'Discovery', 'name': 'Network Scan'},
            'c2_ot':     {'id': 'T0869', 'tactic': 'Command and Control', 'name': 'Standard Protocol (OT)'},
            'exploit':   {'id': 'T0883', 'tactic': 'Execution', 'name': 'Exploitation'},
            'impact':    {'id': 'T0814', 'tactic': 'Impact', 'name': 'DoS / Process Impact'},
            'lateral':   {'id': 'T0866', 'tactic': 'Lateral Movement', 'name': 'Remote Services'}
        }

    def procesar(self, doc):
        detected = []
        mitre_info = {"mitre_score": 1, "mitre_msg": "Info", "mitre_tactics": [], "mitre_techniques": []}

        # Detección basada en la traducción humana
        desc = doc.get('comando_humano', '')

        if doc['source'] == 'snort':
            msg = doc.get('message', '').lower()
            if 'dos' in msg: detected.append(self.mitre_rules['impact'])
            else: detected.append(self.mitre_rules['discovery'])
            
        elif doc['protocol'] == 'iec104':
            detected.append(self.mitre_rules['c2_ot'])
            
            # Reglas más finas basadas en la traducción
            if 'Comando' in desc: 
                # Un comando es potencialmente peligroso si es anomalía
                pass 
            if 'Interrogación' in desc and doc.get('ai_score', 0) < -0.6:
                detected.append(self.mitre_rules['discovery'])
        
        # IA Check
        if doc.get('ai_score', 0) < -0.6:
             detected.append(self.mitre_rules['discovery'])

        # Scoring
        tactics = set(); techniques = set()
        score = 1; msg = "Monitorización Normal"

        for rule in detected:
            tactics.add(rule['tactic']); techniques.add(rule['id'])

        if 'Impact' in tactics: score = 25; msg = "CRÍTICO: Impacto Operativo (T0814)"
        elif 'Command and Control' in tactics: score = 10; msg = "ALERTA: Tráfico SCADA"
        elif 'Discovery' in tactics: score = 5; msg = "BAJO: Escaneo"

        mitre_info['mitre_score'] = score
        mitre_info['mitre_msg'] = msg
        mitre_info['mitre_tactics'] = list(tactics)
        mitre_info['mitre_techniques'] = list(techniques)
        
        return mitre_info

class RiskFusionEngine:
    def __init__(self):
        self.mitre = MitreICSCorrelator()
        self.inventory = {}
        self.load_inventory()

    def load_inventory(self):
        try:
            with open('/app/ot_inventory.json', 'r') as f:
                data = json.load(f)
                for item in data: self.inventory[item.get('ip')] = item.get('criticality', 'LOW')
            print(f"✅ Inventario cargado: {len(self.inventory)} activos.", flush=True)
        except: pass

    def evaluar_riesgo(self, doc, anomaly_score):
        mitre_data = self.mitre.procesar(doc)
        
        dst_ip = doc.get('dst_ip', '0.0.0.0')
        criticidad = self.inventory.get(dst_ip, 'LOW')
        impacto = 1
        if criticidad == 'CRITICAL': impacto = 5
        elif criticidad == 'HIGH': impacto = 3
        
        probabilidad = max(mitre_data['mitre_score'] // 5, 1)
        if anomaly_score < -0.7: probabilidad = 5
        
        total_score = probabilidad * impacto
        label = "BAJO"
        if total_score >= 15: label = "CRÍTICO"
        elif total_score >= 8: label = "MEDIO"

        doc.update(mitre_data)
        doc.update({
            "risk_total_score": total_score,
            "risk_label": label,
            "risk_impact": impacto,
            "risk_probability": probabilidad
        })
        return doc

# ================= NORMALIZACIÓN ROBUSTA =================

def conectar_servicios():
    r = None; es = None
    while not r:
        try: r = redis.Redis(host=REDIS_HOST, port=6379, db=0, decode_responses=True); r.ping(); print("✅ Redis Listo", flush=True)
        except: time.sleep(2)
    while not es:
        try: es = Elasticsearch([f"http://{ELASTIC_HOST}:9200"]); es.ping(); print("✅ Elastic Listo", flush=True)
        except: time.sleep(5)
    return r, es

def normalizar_evento(raw_json):
    try:
        event = json.loads(raw_json)
        file_path = event.get('log', {}).get('file', {}).get('path', '')
        message_raw = event.get('message', '{}')
        
        zeek_data = {}
        if isinstance(message_raw, str):
            try: zeek_data = json.loads(message_raw)
            except: pass
        elif isinstance(message_raw, dict): zeek_data = message_raw

        doc = {
            "@timestamp": datetime.now().isoformat(),
            "raw_log": str(message_raw)[:500],
            "src_ip": "0.0.0.0", "dst_ip": "0.0.0.0", "dst_port": 0,
            "protocol": "unknown", "source": "unknown",
            "comando_humano": "N/A" # Nuevo campo para el Dashboard
        }

        # 1. SNORT
        if "snort" in file_path or event.get('fields', {}).get('source_type') == 'snort':
            doc['source'] = 'snort'; doc['protocol'] = 'ids_alert'
            doc['comando_humano'] = "🚨 Alerta de Intrusión (IDS)"
            ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', str(message_raw))
            if len(ips) >= 1: doc['src_ip'] = ips[0]
            if len(ips) >= 2: doc['dst_ip'] = ips[1]

        # 2. ZEEK
        else:
            doc['source'] = 'zeek'
            doc['src_ip'] = zeek_data.get('id.orig_h') or zeek_data.get('id', {}).get('orig_h', '0.0.0.0')
            doc['dst_ip'] = zeek_data.get('id.resp_h') or zeek_data.get('id', {}).get('resp_h', '0.0.0.0')
            doc['dst_port'] = zeek_data.get('id.resp_p') or zeek_data.get('id', {}).get('resp_p', 0)
            
            if "iec104" in file_path:
                doc['protocol'] = 'iec104'
                sub_source = os.path.basename(file_path)
                doc['sub_source'] = sub_source
                # APLICAMOS LA TRADUCCIÓN AQUÍ
                doc['comando_humano'] = traducir_iec104(sub_source, str(message_raw))
                print(f"🏭 {doc['comando_humano']}", flush=True)

            elif "conn.log" in file_path:
                doc['protocol'] = zeek_data.get('proto', 'tcp')
                doc['comando_humano'] = f"Conexión {doc['protocol'].upper()}"
            elif "dns.log" in file_path:
                doc['protocol'] = 'dns'
                doc['comando_humano'] = "Resolución DNS"
            
        return doc
    except Exception as e: return None

# ================= MAIN LOOP =================
def main():
    print("🧠 SIS Core v3.0: Iniciando con Clasificación Fina...", flush=True)
    r, es = conectar_servicios()
    engine = RiskFusionEngine()
    model = IsolationForest(contamination=IA_CONTAMINATION, n_jobs=-1)
    
    stats = {'total': 0, 'snort': 0}
    history = deque(maxlen=IA_WINDOW_SIZE)
    is_trained = False
    last_tick = time.time()

    print("🚀 Sistema listo y clasificando...", flush=True)

    while True:
        try:
            item = r.blpop(REDIS_KEY, timeout=1)
            
            if time.time() - last_tick > 1.0:
                if stats['total'] > 0:
                    history.append([stats['snort'], stats['total']])
                    stats = {'total': 0, 'snort': 0}
                    if len(history) > 20 and not is_trained:
                        try: model.fit(list(history)); is_trained = True; print("🤖 IA Entrenada", flush=True)
                        except: pass
                last_tick = time.time()

            if not item: continue

            doc = normalizar_evento(item[1])
            if not doc: continue

            ai_score = 0.5
            if is_trained:
                try: 
                    feat = [[1 if doc['source']=='snort' else 0, 1]] 
                    ai_score = float(model.decision_function(feat)[0])
                except: pass
            
            doc['ai_score'] = ai_score
            final_doc = engine.evaluar_riesgo(doc, ai_score)
            es.index(index=INDEX_NAME, document=final_doc)

            stats['total'] += 1
            if final_doc['source'] == 'snort': stats['snort'] += 1

        except Exception as e:
            print(f"🔥 Error: {e}", flush=True); time.sleep(1)

if __name__ == "__main__":
    main()