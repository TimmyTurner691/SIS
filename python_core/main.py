import time
import json
import redis
import os
import re
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime
from collections import deque
from elasticsearch import Elasticsearch

# ================= CONFIGURACIÓN =================
REDIS_HOST = 'redis'
ELASTIC_HOST = 'http://elasticsearch:9200'
INDEX_NAME = 'sis-logs-v1'

# Rutas dentro del contenedor 'cerebro'
LOG_FILES = {
    'snort': '/var/log/snort/alert',
    'zeek_conn': '/var/log/zeek/conn.log',
    'zeek_iec104': '/var/log/zeek/iec104.log'
}

# Configuración IA
IA_WINDOW_SIZE = 200
IA_CONTAMINATION = 0.05

# ================= CONEXIONES =================
def connect_services():
    # 1. Redis
    r = None
    while not r:
        try:
            r = redis.Redis(host=REDIS_HOST, port=6379, db=0, decode_responses=True)
            r.ping()
            print("✅ Redis conectado.", flush=True)
        except:
            print("⏳ Esperando a Redis...", flush=True)
            time.sleep(2)

    # 2. Elasticsearch
    es = None
    while not es:
        try:
            es = Elasticsearch([ELASTIC_HOST])
            if es.ping():
                print("✅ Elasticsearch conectado.", flush=True)
            else:
                raise Exception("Ping fallido")
        except:
            print("⏳ Esperando a Elasticsearch...", flush=True)
            time.sleep(5)
            es = None
    return r, es

# ================= PARSERS INTELIGENTES =================
def parse_snort(line):
    try:
        msg_match = re.search(r'\[\*\*\] (.*?) \[\*\*\]', line)
        ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
        src = ips[0] if len(ips) > 0 else "0.0.0.0"
        dst = ips[1] if len(ips) > 1 else "0.0.0.0"

        return {
            "source": "snort",
            "event_type": "alert",
            "message": msg_match.group(1) if msg_match else "Snort Alert",
            "src_ip": src,
            "dst_ip": dst,
            "raw_log": line.strip(),
            "severity": "high"
        }
    except: return None

def parse_zeek(line, log_type="conn"):
    """
    Parser Híbrido MEJORADO: Soporta JSON, TSV y extrae campos SCADA (IEC104)
    """
    if not line or line.startswith('#'): return None
    
    doc = {}

    # --- 1. EXTRACCIÓN BÁSICA (JSON O TSV) ---
    try:
        # A) Intento JSON
        try:
            data = json.loads(line)
            doc = {
                "source": "zeek",
                "sub_source": log_type,
                "src_ip": data.get('id.orig_h') or data.get('id', {}).get('orig_h'),
                "dst_ip": data.get('id.resp_h') or data.get('id', {}).get('resp_h'),
                "protocol": data.get('proto', 'unknown'), 
                "raw_log": str(data)[:500],
                "severity": "info"
            }
            if data.get('service') == 'iec104':
                doc['protocol'] = 'iec104'

        except json.JSONDecodeError:
            # B) Fallback TSV (El formato de tus logs actuales)
            parts = line.split('\t')
            if len(parts) < 5: return None 
            
            doc = {
                "source": "zeek",
                "sub_source": log_type,
                "src_ip": parts[2] if len(parts) > 2 else "0.0.0.0",
                "dst_ip": parts[4] if len(parts) > 4 else "0.0.0.0",
                "protocol": "unknown",
                "raw_log": line[:800], 
                "severity": "info"
            }
            
            # Detección básica de protocolo
            if "iec104" in line or "2404" in line:
                doc['protocol'] = 'iec104'

    except Exception as e: 
        return None

    # --- 2. LÓGICA DE EXTRACCIÓN SCADA (IEC-104) ---
    # Inicializamos siempre para evitar KeyError en Dashboard
    doc['instruccion'] = "N/A"
    doc['tipo_trama'] = "N/A"

    if doc.get('protocol') == 'iec104' or 'iec104' in doc.get('raw_log', ''):
        doc['protocol'] = 'iec104'
        
        # A) Buscar la INSTRUCCIÓN (ej: iec104::M_EI_NA_1)
        match_instr = re.search(r'iec104::([A-Za-z0-9_]+)', doc['raw_log'])
        if match_instr:
            doc['instruccion'] = match_instr.group(1)
        
        # B) Buscar el TIPO DE TRAMA (I, S, U) aislado entre tabulaciones
        match_type = re.search(r'\t([ISU])\t', doc['raw_log'])
        if match_type:
            raw_type = match_type.group(1)
            if raw_type == 'I': doc['tipo_trama'] = "I (Datos)"
            elif raw_type == 'S': doc['tipo_trama'] = "S (Supervisión)"
            elif raw_type == 'U': doc['tipo_trama'] = "U (Control)"

    return doc

# ================= MAIN LOOP =================
def main():
    r, es = connect_services()
    
    # Modelo ML
    model = IsolationForest(contamination=IA_CONTAMINATION, n_jobs=-1)
    history = deque(maxlen=IA_WINDOW_SIZE)
    is_trained = False

    # Control de Archivos
    file_pointers = {k: 0 for k in LOG_FILES}
    
    # Ir al final de archivos existentes para no procesar el pasado
    for k, path in LOG_FILES.items():
        if os.path.exists(path):
            file_pointers[k] = os.path.getsize(path)

    print("🚀 SIS Core: Ingesta Híbrida SCADA Activada", flush=True)

    while True:
        time.sleep(1)
        
        batch_events = []
        stats_snort = 0
        stats_total = 0

        for key, path in LOG_FILES.items():
            if not os.path.exists(path): continue
            
            try:
                current_size = os.path.getsize(path)
                if current_size < file_pointers[key]:
                    file_pointers[key] = 0 # Rotación detectada
                
                if current_size > file_pointers[key]:
                    with open(path, 'r') as f:
                        f.seek(file_pointers[key])
                        for line in f:
                            doc = None
                            if key == 'snort':
                                doc = parse_snort(line)
                                if doc: stats_snort += 1
                            else:
                                # Aquí llamamos a la función mejorada
                                doc = parse_zeek(line, key)
                            
                            if doc:
                                doc['@timestamp'] = datetime.now().isoformat()
                                batch_events.append(doc)
                                stats_total += 1
                    
                    file_pointers[key] = current_size
            except Exception as e:
                print(f"⚠️ Error leyendo {path}: {e}")

        # --- LÓGICA IA ---
        anomaly_score = 0.0
        is_anomaly = False
        
        if stats_total > 0 or len(history) > 0:
            history.append([stats_snort, stats_total])

        if len(history) >= 20:
            if not is_trained:
                model.fit(list(history))
                is_trained = True
                print("🧠 IA Entrenada y Activa", flush=True)
            
            features = np.array([[stats_snort, stats_total]])
            pred = model.predict(features)
            if pred[0] == -1:
                is_anomaly = True
                anomaly_score = model.decision_function(features)[0]

        # --- INDEXACIÓN ELASTIC ---
        for doc in batch_events:
            doc['ai_anomaly'] = is_anomaly
            doc['ai_score'] = float(anomaly_score)
            try:
                es.index(index=INDEX_NAME, document=doc)
            except Exception as e:
                print(f"❌ Error indexando en Elastic: {e}")

        # --- REPORTE REDIS ---
        if stats_total > 0:
            color = "VERDE"
            if is_anomaly: color = "AMARILLO"
            if stats_snort > 0: color = "ROJO_CRITICO"
            
            print(f"📦 Procesados: {stats_total} | SCADA Logs: {'iec104' in path} | Estado: {color}", flush=True)

if __name__ == "__main__":
    main()