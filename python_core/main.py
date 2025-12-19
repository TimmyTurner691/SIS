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

# ================= CONFIGURACIÓN PROD =================
REDIS_HOST = 'redis'
ELASTIC_HOST = 'http://elasticsearch:9200'
INDEX_NAME = 'sis-logs-v1' # Índice versionado

# Rutas de logs (Volúmenes Docker)
LOG_FILES = {
    'snort': '/var/log/snort/alert',
    'zeek_conn': '/var/log/zeek/conn.log',
    'zeek_iec104': '/var/log/zeek/iec104.log'
}

# Configuración ML
IA_WINDOW_SIZE = 200
IA_CONTAMINATION = 0.05

# ================= CONEXIONES ROBUSTAS =================
def connect_services():
    # 1. Redis con reintentos
    r = None
    while not r:
        try:
            r = redis.Redis(host=REDIS_HOST, port=6379, db=0, decode_responses=True)
            r.ping()
            print("✅ Redis conectado.", flush=True)
        except:
            print("⏳ Esperando a Redis...", flush=True)
            time.sleep(2)

    # 2. Elasticsearch con reintentos
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

# ================= PARSERS (ETL) =================
def parse_snort(line):
    # Extracción robusta de IPs y mensaje
    try:
        # Regex para capturar timestamp, IPs y mensaje
        msg_match = re.search(r'\[\*\*\] (.*?) \[\*\*\]', line)
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line) # Captura primera IP
        
        return {
            "source": "snort",
            "event_type": "alert",
            "message": msg_match.group(1) if msg_match else "Snort Alert",
            "raw_log": line.strip(),
            "severity": "high"
        }
    except: return None

def parse_zeek(line, log_type="conn"):
    if line.startswith('#'): return None
    try:
        parts = line.split('\t')
        if len(parts) < 5: return None
        
        # Mapeo básico de campos Zeek
        return {
            "source": "zeek",
            "sub_source": log_type,
            "src_ip": parts[2] if len(parts) > 2 else None,
            "dst_ip": parts[4] if len(parts) > 4 else None,
            "protocol": parts[6] if len(parts) > 6 else "unknown",
            "message": f"Connection {parts[6]}",
            "raw_log": line[:200], # Truncar para ahorrar espacio si es muy largo
            "severity": "info"
        }
    except: return None

# ================= CORE LOGIC =================
def main():
    r, es = connect_services()
    
    # Inicializar IA
    model = IsolationForest(contamination=IA_CONTAMINATION, n_jobs=-1)
    history = deque(maxlen=IA_WINDOW_SIZE)
    is_trained = False

    # Punteros de archivos (Persistencia de lectura en memoria del proceso)
    file_pointers = {k: 0 for k in LOG_FILES}
    
    # Posicionar al final para no re-leer logs viejos al reiniciar contenedor
    for k, path in LOG_FILES.items():
        if os.path.exists(path):
            file_pointers[k] = os.path.getsize(path)

    print("🚀 SIS Core: Ingesta y Análisis Activo", flush=True)

    while True:
        time.sleep(1) # Sampling rate rápido
        
        batch_events = []
        stats_snort = 0
        stats_total = 0

        # 1. LEER Y PARSEAR LOGS
        for key, path in LOG_FILES.items():
            if not os.path.exists(path): continue
            
            # Detectar rotación de logs (si el archivo es más chico que antes)
            current_size = os.path.getsize(path)
            if current_size < file_pointers[key]:
                file_pointers[key] = 0
            
            if current_size > file_pointers[key]:
                with open(path, 'r') as f:
                    f.seek(file_pointers[key])
                    for line in f:
                        doc = None
                        if key == 'snort':
                            doc = parse_snort(line)
                            if doc: stats_snort += 1
                        else:
                            doc = parse_zeek(line, key)
                        
                        if doc:
                            # Timestamp ISO 8601 para Elastic
                            doc['@timestamp'] = datetime.now().isoformat()
                            batch_events.append(doc)
                            stats_total += 1
                
                file_pointers[key] = current_size

        # 2. ANÁLISIS DE IA (Isolation Forest)
        anomaly_score = 0
        is_anomaly = False
        
        history.append([stats_snort, stats_total])
        if len(history) >= 20: # Mínimo para entrenar
            if not is_trained:
                model.fit(list(history))
                is_trained = True
            
            # Predecir sobre el batch actual
            features = np.array([[stats_snort, stats_total]])
            pred = model.predict(features) # -1 anomalo, 1 normal
            if pred[0] == -1:
                is_anomaly = True
                anomaly_score = model.decision_function(features)[0]

        # 3. INDEXAR EN ELASTICSEARCH (Bulk o individual)
        # En prod usaríamos bulk API, aquí loop simple para claridad
        for doc in batch_events:
            # Enriquecemos el log con la decisión de la IA
            doc['ai_anomaly'] = is_anomaly
            doc['ai_score'] = float(anomaly_score)
            
            try:
                es.index(index=INDEX_NAME, document=doc)
            except Exception as e:
                print(f"❌ Error indexing: {e}")

        # 4. ACTUALIZAR ESTADO EN REDIS (Para Dashboard en vivo)
        # Calculamos riesgo
        risk_level = 0
        status_msg = "Sistema Nominal"
        color = "VERDE"

        if is_anomaly:
            risk_level = 15
            status_msg = "Anomalía de Tráfico (IA)"
            color = "AMARILLO"
        
        if stats_snort > 0:
            risk_level = 25
            status_msg = f"ATAQUE DETECTADO ({stats_snort} alertas)"
            color = "ROJO_CRITICO"

        state_payload = {
            "updated_at": datetime.now().strftime("%H:%M:%S"),
            "risk_score": risk_level,
            "status_text": status_msg,
            "color_code": color,
            "ai_trained": is_trained
        }
        r.set("sis:system_state", json.dumps(state_payload))
        
        if stats_total > 0:
            print(f"📦 Procesados {stats_total} eventos. Estado: {color}", flush=True)

if __name__ == "__main__":
    main()