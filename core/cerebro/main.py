import time
import json
import redis
import os
import re
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from datetime import datetime
from collections import deque
from elasticsearch import Elasticsearch, helpers
import warnings
from elasticsearch import ElasticsearchWarning
from discovered_assets import DiscoveredAssetStore

warnings.filterwarnings("ignore", category=ElasticsearchWarning)

try:
    from utils_alert import send_email_alert
except ImportError:
    def send_email_alert(subject, body, level):
        print(f"📧 [EMAIL SIMULADO] {subject}", flush=True)

# ================= CONFIGURACIÓN NITRO =================
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
ELASTIC_HOST = os.getenv("ELASTIC_HOST", "elasticsearch")
ELASTIC_PORT = int(os.getenv("ELASTIC_PORT", "9200"))
REDIS_KEY = os.getenv("REDIS_KEY", "sis_queue")
INDEX_NAME = os.getenv("SIS_INDEX_NAME", "sis-logs-v1")
DISCOVERED_ASSETS_INDEX = os.getenv("SIS_DISCOVERED_ASSETS_INDEX", "sis-discovered-assets-v2")
INVENTORY_FILE = os.getenv("SIS_INVENTORY_PATH", "/app/ot_inventory.json")

IA_WINDOW_SIZE = 500
IA_CONTAMINATION = 0.05
BATCH_SIZE = 5000       
FLUSH_INTERVAL = 0.5    

FLOOD_THRESHOLD = 100 

# ================= LÓGICA DE TRADUCCIÓN =================
# ... (Sin cambios en traducir_iec104) ...
def traducir_iec104(sub_source, raw_log_str):
    sub = sub_source.lower()
    raw = raw_log_str.upper()
    if 'c_sc' in sub: return "⚙️ Comando Simple (Switch/Breaker)"
    if 'c_dc' in sub: return "⚙️ Comando Doble (Breaker)"
    if 'c_rc' in sub: return "⚙️ Comando de Regulación (Set Point)"
    if 'c_ic' in sub: return "❓ Interrogación General (Polling)"
    if 'm_me' in sub: return "📈 Telemetría (Medida Analógica)"
    if 'm_sp' in sub: return "📡 Info Punto Simple"
    if 'apci_u' in sub:
        if 'STARTDT' in raw: return "🟢 Inicio Conexión (STARTDT)"
        if 'STOPDT'  in raw: return "🔴 Fin Conexión (STOPDT)"
        if 'TESTFR'  in raw: return "💓 Latido (Test Frame)"
        return "🔌 Gestión de Conexión"
    if 'apci_s' in sub: return "🛡️ Confirmación (ACK)"
    if 'apci_i' in sub: return "📦 Datos (I-Format)"
    return "📦 Tráfico Industrial Genérico"

# ================= MOTORES DE INTELIGENCIA =================
# ... (Sin cambios en MitreICSCorrelator y RiskFusionEngine) ...
class MitreICSCorrelator:
    def __init__(self):
        self.mitre_rules = {
            'discovery': {'id': 'T0846', 'tactic': 'Discovery', 'name': 'Network Scan'},
            'c2_ot':     {'id': 'T0869', 'tactic': 'Command and Control', 'name': 'Standard Protocol (OT)'},
            'exploit':   {'id': 'T0883', 'tactic': 'Execution', 'name': 'Exploitation'},
            'impact':    {'id': 'T0814', 'tactic': 'Impact', 'name': 'DoS / Process Impact'},
        }

    def procesar(self, doc, is_flood):
        detected = []
        mitre_info = {"mitre_score": 1, "mitre_msg": "Info", "mitre_tactics": [], "mitre_techniques": []}

        if is_flood:
            detected.append(self.mitre_rules['impact'])
            detected.append(self.mitre_rules['c2_ot'])
            score = 25
            msg = "CRÍTICO: Inundación de Red (DoS)"
        else:
            desc = doc.get('comando_humano', '')
            if doc['source'] == 'snort':
                snort_text = f"{doc.get('message', '')} {doc.get('raw_log', '')}".lower()

                if 'dos' in snort_text or 'flood' in snort_text or 'critical flood' in snort_text:
                    detected.append(self.mitre_rules['impact'])
                    detected.append(self.mitre_rules['c2_ot'])
                else:
                    detected.append(self.mitre_rules['discovery'])
            elif doc['protocol'] == 'iec104':
                detected.append(self.mitre_rules['c2_ot'])
                if 'Interrogación' in desc and doc.get('ai_score', 0) < -0.35:
                    detected.append(self.mitre_rules['discovery'])
            
            if doc.get('ai_score', 0) < -0.35:
                 detected.append(self.mitre_rules['discovery'])

            score = 1; msg = "Monitorización Normal"
            tactics = set()
            for rule in detected: tactics.add(rule['tactic'])

            if 'Impact' in tactics: score = 25; msg = "CRÍTICO: Impacto Operativo"
            elif 'Command and Control' in tactics: score = 10; msg = "ALERTA: Tráfico SCADA"
            elif 'Discovery' in tactics: score = 5; msg = "BAJO: Escaneo"

        tactics = set(); techniques = set()
        for rule in detected: tactics.add(rule['tactic']); techniques.add(rule['id'])

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
            with open(INVENTORY_FILE, 'r') as f:
                data = json.load(f)
                for item in data: self.inventory[item.get('ip')] = item.get('criticality', 'LOW')
        except: pass

    def evaluar_riesgo(self, doc, anomaly_score, is_flood):
        mitre_data = self.mitre.procesar(doc, is_flood)
        dst_ip = doc.get('dst_ip', '0.0.0.0')
        criticidad = self.inventory.get(dst_ip, 'LOW')
        
        impacto = 1
        if criticidad == 'CRITICAL': impacto = 5
        elif criticidad == 'HIGH': impacto = 3
        
        if is_flood:
            probabilidad = 5; impacto = 5
        else:
            probabilidad = max(mitre_data['mitre_score'] // 5, 1)
            if anomaly_score < -0.35: probabilidad = 4 
        
        total_score = probabilidad * impacto
        
        label = "BAJO"
        if total_score >= 15: label = "CRÍTICO"
        elif total_score >= 8: label = "MEDIO"

        doc.update(mitre_data)
        doc.update({
            "risk_total_score": total_score, 
            "risk_label": label,
            "risk_impact": impacto, 
            "risk_probability": probabilidad,
            "ai_score": anomaly_score
        })
        return doc

# ================= HELPER FUNCTIONS =================
def conectar_servicios():
    r = None; es = None
    while not r:
        try: r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True); r.ping(); print("✅ Redis Listo", flush=True)
        except: time.sleep(2)
    
    while not es:
        try: 
            es = Elasticsearch([f"http://{ELASTIC_HOST}:{ELASTIC_PORT}"])
            if es.ping():
                print("✅ Elastic Listo", flush=True)
            else:
                print("⚠️ Elastic conectado pero no responde al Ping...", flush=True)
                es = None
                time.sleep(5)
        except Exception as e: 
            print(f"❌ Error conectando a http://{ELASTIC_HOST}:{ELASTIC_PORT} -> {e}", flush=True)
            time.sleep(5)
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
            "protocol": "unknown", "source": "unknown", "comando_humano": "N/A"
        }

        if "snort" in file_path or event.get('fields', {}).get('source_type') == 'snort':
            doc['source'] = 'snort'
            doc['protocol'] = 'ids_alert'
            doc['comando_humano'] = "🚨 Alerta IDS"
            doc['message'] = str(message_raw)

            ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', str(message_raw))
            if len(ips) >= 1:
                doc['src_ip'] = ips[0]
            if len(ips) >= 2:
                doc['dst_ip'] = ips[1]
        else:
            doc['source'] = 'zeek'
            doc['src_ip'] = zeek_data.get('id.orig_h') or zeek_data.get('id', {}).get('orig_h', '0.0.0.0')
            doc['dst_ip'] = zeek_data.get('id.resp_h') or zeek_data.get('id', {}).get('resp_h', '0.0.0.0')
            doc['dst_port'] = zeek_data.get('id.resp_p') or zeek_data.get('id', {}).get('resp_p', 0)
            if "iec104" in file_path:
                doc['protocol'] = 'iec104'; doc['sub_source'] = os.path.basename(file_path)
                doc['comando_humano'] = traducir_iec104(doc['sub_source'], str(message_raw))
            elif "conn.log" in file_path: doc['protocol'] = zeek_data.get('proto', 'tcp')
        return doc
    except: return None

def reset_brain_state():
    model = IsolationForest(contamination=IA_CONTAMINATION, n_jobs=-1)
    stats = {'total': 0, 'snort': 0}
    history = deque(maxlen=IA_WINDOW_SIZE)
    is_trained = False
    alert_cooldown = {}
    metrics_start_time = time.time()
    metrics_count = 0
    current_eps = 0.0
    last_print_time = time.time()

    return {
        "model": model,
        "stats": stats,
        "history": history,
        "is_trained": is_trained,
        "alert_cooldown": alert_cooldown,
        "metrics_start_time": metrics_start_time,
        "metrics_count": metrics_count,
        "current_eps": current_eps,
        "last_print_time": last_print_time,
    }


def wipe_elasticsearch_index(es):
    try:
        if es.indices.exists(index=INDEX_NAME):
            es.indices.delete(index=INDEX_NAME)
            print(f"🗑️ Índice eliminado: {INDEX_NAME}", flush=True)

        es.indices.create(index=INDEX_NAME, ignore=400)
        print(f"✅ Índice recreado: {INDEX_NAME}", flush=True)
    except Exception as e:
        print(f"⚠️ Error reiniciando Elasticsearch: {e}", flush=True)


def clear_source_logs():
    log_paths = [
        "/logs/snort/alert",
    ]

    for file_path in log_paths:
        try:
            p = Path(file_path)
            if p.exists():
                p.write_text("")
                print(f"🧹 Log limpiado: {file_path}", flush=True)
        except Exception as e:
            print(f"⚠️ No se pudo limpiar {file_path}: {e}", flush=True)

    zeek_dirs = [
        "/logs/zeek",
        "/pcap/logs/live",
        "/pcap/logs",
    ]

    for zeek_dir in zeek_dirs:
        try:
            p = Path(zeek_dir)
            if p.exists() and p.is_dir():
                for f in p.glob("*.log"):
                    try:
                        f.write_text("")
                        print(f"🧹 Log Zeek limpiado: {f}", flush=True)
                    except Exception as inner_e:
                        print(f"⚠️ No se pudo limpiar {f}: {inner_e}", flush=True)
        except Exception as e:
            print(f"⚠️ Error revisando directorio {zeek_dir}: {e}", flush=True)


def full_reset_demo(es, r, engine):
    print("🧹 COMANDO RECIBIDO: Ejecutando RESET DEMO TOTAL...", flush=True)

    # 1. Borrar cola Redis
    try:
        r.delete(REDIS_KEY)
        print("✅ Cola Redis vaciada.", flush=True)
    except Exception as e:
        print(f"⚠️ Error vaciando Redis: {e}", flush=True)

    # 2. Reiniciar índice Elasticsearch
    wipe_elasticsearch_index(es)

    # 3. Limpiar logs fuente
    clear_source_logs()

    # 4. Recargar inventario por si hubo cambios
    try:
        engine.load_inventory()
    except Exception as e:
        print(f"⚠️ Error recargando inventario: {e}", flush=True)

    print("✅ RESET DEMO TOTAL completado.", flush=True)

    # 5. Devolver estado limpio para la IA
    return reset_brain_state()

# ================= MAIN LOOP CON MONITOR DE CONSOLA =================
def main():
    print(f"🚀 SIS Core v7.2: MONITOR DE CONSOLA ACTIVO", flush=True)
    r, es = conectar_servicios()
    engine = RiskFusionEngine()
    discovered_assets = DiscoveredAssetStore(es, DISCOVERED_ASSETS_INDEX)

    state = reset_brain_state()
    model = state["model"]
    stats = state["stats"]
    history = state["history"]
    is_trained = state["is_trained"]
    alert_cooldown = state["alert_cooldown"]
    metrics_start_time = state["metrics_start_time"]
    metrics_count = state["metrics_count"]
    current_eps = state["current_eps"]
    last_print_time = state["last_print_time"]

    while True:
        try:
            # --- NUEVO: CHECK DE COMANDOS DE CONTROL ---

            # 1. Reset IA
            if r.exists("cmd_reset_brain"):
                print("♻️ COMANDO RECIBIDO: Borrando memoria IA...", flush=True)

                state = reset_brain_state()
                model = state["model"]
                stats = state["stats"]
                history = state["history"]
                is_trained = state["is_trained"]
                alert_cooldown = state["alert_cooldown"]
                metrics_start_time = state["metrics_start_time"]
                metrics_count = state["metrics_count"]
                current_eps = state["current_eps"]
                last_print_time = state["last_print_time"]

                r.delete("cmd_reset_brain")
                r.delete(REDIS_KEY)

                print("✅ Memoria IA borrada. Esperando tráfico nuevo...", flush=True)
                time.sleep(1)
                continue

            # 2. Reset Demo Total
            if r.exists("cmd_full_reset_demo"):
                state = full_reset_demo(es, r, engine)

                model = state["model"]
                stats = state["stats"]
                history = state["history"]
                is_trained = state["is_trained"]
                alert_cooldown = state["alert_cooldown"]
                metrics_start_time = state["metrics_start_time"]
                metrics_count = state["metrics_count"]
                current_eps = state["current_eps"]
                last_print_time = state["last_print_time"]

                r.delete("cmd_full_reset_demo")

                print("✅ Sistema reiniciado para demo. Estado limpio.", flush=True)
                time.sleep(2)
                continue

            # 3. Forzar re-entrenamiento
            if r.exists("cmd_force_train"):
                print("🎓 COMANDO: Forzando re-entrenamiento...", flush=True)
                is_trained = False
                r.delete("cmd_force_train")

            # 4. Re-escanear manualmente redes descubiertas
            if r.exists("cmd_rescan_discovered_networks"):
                print("🔁 COMANDO: Re-escaneando redes descubiertas...", flush=True)
                scheduled = discovered_assets.rescan_discovered_networks()
                r.set("cmd_rescan_discovered_networks_result", str(scheduled), ex=120)
                r.delete("cmd_rescan_discovered_networks")

            # ------------------------------------

            batch_raw = []
            
            try:
                batch_raw = r.lpop(REDIS_KEY, BATCH_SIZE)
                if not batch_raw: batch_raw = []
            except:
                while len(batch_raw) < BATCH_SIZE:
                    item = r.lpop(REDIS_KEY)
                    if item: batch_raw.append(item)
                    else: break
            
            if not batch_raw:
                item_block = r.blpop(REDIS_KEY, timeout=1)
                if item_block: batch_raw.append(item_block[1])
                else: continue

            batch_len = len(batch_raw)
            metrics_count += batch_len
            elapsed_metrics = time.time() - metrics_start_time
            
            if elapsed_metrics >= 1.0:
                current_eps = metrics_count / elapsed_metrics
                lag = r.llen(REDIS_KEY)
                metrics_start_time = time.time()
                metrics_count = 0

            IS_FLOOD = True if current_eps > FLOOD_THRESHOLD else False

            stats['total'] += batch_len
            if len(history) >= 20 and not is_trained:
                 try: model.fit(list(history)); is_trained = True; print("🤖 IA Entrenada", flush=True)
                 except: pass

            ai_score = 0.5
            if IS_FLOOD: ai_score = -1.0
            elif is_trained:
                try: ai_score = float(model.decision_function([[stats['snort'], stats['total']]])[0])
                except: pass

            # Monitor de consola (cada 2s)
            if time.time() - last_print_time > 2.0:
                icon = "🟢"
                status_msg = "NORMAL"
                
                if ai_score < -0.35: 
                    icon = "⚠️"
                    status_msg = "ANOMALÍA SUTIL"
                if IS_FLOOD: 
                    icon = "🔥"
                    status_msg = "FLOOD / DOS"
                
                if current_eps > 0 or ai_score < 0:
                    print(f"{icon} [IA MONITOR] Score: {ai_score:.3f} | EPS: {current_eps:.0f} | Estado: {status_msg}", flush=True)
                
                last_print_time = time.time()

            actions_bulk = []
            for raw_json in batch_raw:
                doc = normalizar_evento(raw_json)
                if not doc: continue
                
                final_doc = engine.evaluar_riesgo(doc, ai_score, IS_FLOOD)
                discovered_assets.process_event(raw_json, final_doc)
                
                if final_doc.get('risk_label') == 'CRÍTICO' and not IS_FLOOD:
                    ip_atacante = final_doc.get('src_ip', 'unknown')
                    now = time.time()
                    if (now - alert_cooldown.get(ip_atacante, 0)) > 60:
                        asunto = f"🚨 {final_doc.get('mitre_msg')}"
                        cuerpo = f"CRÍTICO Detectado\nEPS: {current_eps:.1f}\nIP: {ip_atacante}"
                        send_email_alert(asunto, cuerpo, level="CRITICAL")
                        alert_cooldown[ip_atacante] = now

                actions_bulk.append({"_index": INDEX_NAME, "_source": final_doc})
                if final_doc['source'] == 'snort': stats['snort'] += 1

            if actions_bulk: helpers.bulk(es, actions_bulk)
            
            if not IS_FLOOD or (time.time() % 5 == 0):
                history.append([stats['snort'], stats['total']])
            stats = {'total': 0, 'snort': 0}

        except Exception as e:
            print(f"🔥 Error: {e}", flush=True); time.sleep(1)

if __name__ == "__main__":
    main()