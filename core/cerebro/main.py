import time
import json
import redis
import os
import re
from pathlib import Path
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, helpers
import warnings
from elasticsearch import ElasticsearchWarning
from discovered_assets import DiscoveredAssetStore
from event_filter import contains_ipv6, is_legacy_test_alert, is_unspecified_traffic
from traffic_analysis import EventReplayGuard, TrafficBaselineModel, TrafficRateMonitor

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
DISCOVERED_ASSETS_INDEX = os.getenv("SIS_DISCOVERED_ASSETS_INDEX", "sis-discovered-assets-v3")
INVENTORY_FILE = os.getenv("SIS_INVENTORY_PATH", "/app/ot_inventory.json")

BATCH_SIZE = 5000

DIRECT_LOG_POLL_ENABLED = os.getenv("SIS_DIRECT_LOG_POLL_ENABLED", "false").lower() == "true"
DIRECT_LOG_POLL_INTERVAL = float(os.getenv("SIS_DIRECT_LOG_POLL_INTERVAL", "1.0"))
DIRECT_LOG_MAX_LINES = int(os.getenv("SIS_DIRECT_LOG_MAX_LINES", "1000"))

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
            'c2_ot': {'id': 'T0869', 'tactic': 'Command and Control', 'name': 'Standard Protocol (OT)'},
            'exploit': {'id': 'T0883', 'tactic': 'Execution', 'name': 'Exploitation'},
            'impact': {'id': 'T0814', 'tactic': 'Impact', 'name': 'DoS / Process Impact'},
        }

    def procesar(self, doc, is_flood, anomaly_score):
        detected = []
        text = f"{doc.get('message', '')} {doc.get('raw_log', '')}".lower()
        description = doc.get('comando_humano', '')

        if is_flood:
            detected.extend([self.mitre_rules['impact'], self.mitre_rules['c2_ot']])
            score = 25
            message = "CRÍTICO: Inundación de Red (DoS) confirmada"
        else:
            is_icmp_monitoring = "icmp" in text and "sis icmp detectado" in text
            if "exploit" in text:
                detected.append(self.mitre_rules['exploit'])
            elif doc.get('source') == 'snort' and not is_icmp_monitoring:
                detected.append(self.mitre_rules['discovery'])
            elif doc.get('protocol') == 'iec104':
                detected.append(self.mitre_rules['c2_ot'])
                if 'Interrogación' in description and anomaly_score < -0.15:
                    detected.append(self.mitre_rules['discovery'])

            tactics = {rule['tactic'] for rule in detected}
            if 'Execution' in tactics:
                score, message = 15, "ALERTA: Posible explotación"
            elif 'Command and Control' in tactics:
                score, message = 10, "ALERTA: Tráfico SCADA"
            elif 'Discovery' in tactics:
                score, message = 5, "BAJO: Actividad de descubrimiento"
            else:
                score, message = 1, "Monitorización normal"

        tactics = {rule['tactic'] for rule in detected}
        techniques = {rule['id'] for rule in detected}
        return {
            "mitre_score": score,
            "mitre_msg": message,
            "mitre_tactics": list(tactics),
            "mitre_techniques": list(techniques),
        }


class RiskFusionEngine:
    def __init__(self):
        self.mitre = MitreICSCorrelator()
        self.inventory = {}
        self.load_inventory()

    def load_inventory(self):
        try:
            with open(INVENTORY_FILE, 'r') as stream:
                data = json.load(stream)
                for item in data:
                    self.inventory[item.get('ip')] = item.get('criticality', 'LOW')
        except Exception:
            pass

    def evaluar_riesgo(self, doc, anomaly_score, is_flood, detection_reason=None, traffic_metrics=None):
        mitre_data = self.mitre.procesar(doc, is_flood, anomaly_score)
        criticidad = self.inventory.get(doc.get('dst_ip'), 'LOW')
        impacto = 5 if criticidad == 'CRITICAL' else 3 if criticidad == 'HIGH' else 1

        if is_flood:
            probability = 5
            impacto = 5
        else:
            tactics = set(mitre_data['mitre_tactics'])
            if 'Execution' in tactics:
                probability = 3
            elif 'Command and Control' in tactics or 'Discovery' in tactics:
                probability = 2
            else:
                probability = 1

            # ML is supporting evidence only. It may raise likelihood one level,
            # but cannot turn normal traffic into a critical DoS by itself.
            if anomaly_score < -0.10:
                probability = min(probability + 1, 2 if not tactics else 3)

        total_score = probability * impacto
        label = "CRÍTICO" if total_score >= 15 else "MEDIO" if total_score >= 8 else "BAJO"
        traffic_metrics = traffic_metrics or {}
        doc.update(mitre_data)
        doc.update({
            "risk_total_score": total_score,
            "risk_label": label,
            "risk_impact": impacto,
            "risk_probability": probability,
            "ai_score": anomaly_score,
            "dos_confirmed": bool(is_flood),
            "detection_model_version": 2,
            "detection_reason": detection_reason or "none",
            "traffic_eps": round(float(traffic_metrics.get('accepted_eps', 0.0)), 2),
            "flow_eps": round(float(traffic_metrics.get('max_flow_eps', 0.0)), 2),
        })
        return doc

# ================= HELPER FUNCTIONS =================
def _unique_hosts(*hosts):
    seen = []
    for host in hosts:
        if host and host not in seen:
            seen.append(host)
    return seen


def conectar_servicios():
    r = None; es = None
    redis_hosts = _unique_hosts(REDIS_HOST, "127.0.0.1", "redis")
    elastic_hosts = _unique_hosts(ELASTIC_HOST, "127.0.0.1", "elasticsearch")

    while not r:
        for host in redis_hosts:
            try:
                candidate = redis.Redis(host=host, port=REDIS_PORT, db=0, decode_responses=True)
                candidate.ping()
                r = candidate
                print(f"✅ Redis Listo ({host}:{REDIS_PORT})", flush=True)
                break
            except Exception as e:
                print(f"⚠️ Redis no disponible en {host}:{REDIS_PORT} -> {e}", flush=True)
        if not r:
            time.sleep(2)

    while not es:
        for host in elastic_hosts:
            try:
                candidate = Elasticsearch([f"http://{host}:{ELASTIC_PORT}"])
                if candidate.ping():
                    es = candidate
                    print(f"✅ Elastic Listo ({host}:{ELASTIC_PORT})", flush=True)
                    break
                print(f"⚠️ Elastic conectado pero no responde al Ping en {host}:{ELASTIC_PORT}", flush=True)
            except Exception as e:
                print(f"❌ Error conectando a http://{host}:{ELASTIC_PORT} -> {e}", flush=True)
        if not es:
            time.sleep(5)
    return r, es

def purge_trash_events(es):
    """Elimina históricos TEST, flujos 0.0.0.0 y falsos DoS del detector anterior."""
    query = {
        "query": {
            "bool": {
                "should": [
                    {"match_phrase": {"raw_log": "Ping Detectado en WiFi"}},
                    {"match_phrase": {"message": "Ping Detectado en WiFi"}},
                    {"query_string": {"query": "1000005", "fields": ["raw_log", "message"]}},
                    {
                        "bool": {
                            "filter": [
                                {
                                    "bool": {
                                        "should": [
                                            {"term": {"src_ip": "0.0.0.0"}},
                                            {"term": {"src_ip.keyword": "0.0.0.0"}},
                                        ],
                                        "minimum_should_match": 1,
                                    }
                                },
                                {
                                    "bool": {
                                        "should": [
                                            {"term": {"dst_ip": "0.0.0.0"}},
                                            {"term": {"dst_ip.keyword": "0.0.0.0"}},
                                        ],
                                        "minimum_should_match": 1,
                                    }
                                },
                            ]
                        }
                    },
                    {
                        "query_string": {
                            "query": '"0.0.0.0 -> 0.0.0.0"',
                            "fields": ["raw_log", "message"],
                        }
                    },
                    {
                        "bool": {
                            "filter": [
                                {"match_phrase": {"mitre_msg": "CRÍTICO: Inundación de Red (DoS)"}},
                            ],
                            "must_not": [{"exists": {"field": "dos_confirmed"}}],
                        }
                    },
                    {
                        "bool": {
                            "filter": [
                                {"term": {"dos_confirmed": True}},
                                {
                                    "bool": {
                                        "should": [
                                            {"term": {"protocol": "icmp"}},
                                            {"match_phrase": {"message": "SIS ICMP detectado"}},
                                            {"match_phrase": {"raw_log": "SIS ICMP detectado"}},
                                        ],
                                        "minimum_should_match": 1,
                                    }
                                },
                            ],
                            "must_not": [{"exists": {"field": "detection_model_version"}}],
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        }
    }
    try:
        result = es.delete_by_query(
            index=INDEX_NAME,
            body=query,
            conflicts="proceed",
            refresh=True,
        )
        deleted = result.get("deleted", 0)
        if deleted:
            print(f"🧹 Eliminados {deleted} eventos basura históricos de Elasticsearch", flush=True)
        return deleted
    except Exception as exc:
        print(f"⚠️ No se pudieron purgar eventos basura históricos: {exc}", flush=True)
        return 0


_SNORT_TIMESTAMP_RE = re.compile(
    r"(?<!\d)(\d{2})/(\d{2})-(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?"
)


def _event_epoch(event, message_raw, now=None):
    """Uses sensor time first so replayed log backlogs are not treated as live bursts."""
    now = time.time() if now is None else now
    text = str(message_raw)
    match = _SNORT_TIMESTAMP_RE.search(text)
    if match:
        month, day, hour, minute, second, fraction = match.groups()
        microsecond = int((fraction or "0").ljust(6, "0")[:6])
        current = datetime.fromtimestamp(now, timezone.utc)
        candidate = datetime(
            current.year,
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(second),
            microsecond,
            tzinfo=timezone.utc,
        )
        if candidate.timestamp() > now + 86400:
            candidate = candidate.replace(year=current.year - 1)
        return candidate.timestamp()

    zeek_payload = message_raw if isinstance(message_raw, dict) else {}
    if isinstance(message_raw, str):
        try:
            zeek_payload = json.loads(message_raw)
        except (TypeError, json.JSONDecodeError):
            pass
    try:
        return float(zeek_payload.get("ts"))
    except (AttributeError, TypeError, ValueError):
        pass

    timestamp = event.get("@timestamp")
    if timestamp:
        try:
            return datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return now


def _index_epoch(event, now=None):
    """Uses Filebeat ingestion time for dashboard visibility, falling back to current time."""
    now = time.time() if now is None else now
    timestamp = event.get("@timestamp")
    if timestamp:
        try:
            return datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")).timestamp()
        except (TypeError, ValueError):
            pass
    return now


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

        # Descarta ruido fuera de alcance antes de enriquecer e indexar.
        if contains_ipv6(message_raw) or contains_ipv6(zeek_data):
            return None
        if is_legacy_test_alert(message_raw) or is_legacy_test_alert(event):
            return None

        now_epoch = time.time()
        event_epoch = _event_epoch(event, message_raw, now=now_epoch)
        index_epoch = _index_epoch(event, now=now_epoch)
        doc = {
            "@timestamp": datetime.fromtimestamp(index_epoch, timezone.utc).isoformat(),
            "_event_epoch": event_epoch,
            "raw_log": str(message_raw)[:500],
            "src_ip": "0.0.0.0", "dst_ip": "0.0.0.0", "dst_port": 0,
            "protocol": "unknown", "source": "unknown", "comando_humano": "N/A"
        }

        if "snort" in file_path or event.get('source_type') == 'snort' or event.get('fields', {}).get('source_type') == 'snort':
            doc['source'] = 'snort'
            protocol_match = re.search(r'\{([A-Za-z0-9_-]+)\}', str(message_raw))
            doc['protocol'] = protocol_match.group(1).lower() if protocol_match else 'ids_alert'
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

        if is_unspecified_traffic(doc) or is_unspecified_traffic(message_raw):
            return None
        return doc
    except: return None


def _source_type_for_direct_log(path):
    path_str = str(path)
    if "/snort/" in path_str or path.name == "alert":
        return "snort"
    return "zeek"


def _iter_direct_log_files():
    candidates = []
    zeek_root = Path("/var/log/zeek")
    if zeek_root.exists():
        patterns = ["conn.log", "dns.log", "dhcp.log", "arp.log", "*iec104*.log"]
        for pattern in patterns:
            candidates.extend(zeek_root.rglob(pattern))
    snort_alert = Path("/var/log/snort/alert")
    if snort_alert.exists():
        candidates.append(snort_alert)
    return sorted({path for path in candidates if path.is_file()})


def poll_direct_source_logs(offsets, max_lines=DIRECT_LOG_MAX_LINES):
    if not DIRECT_LOG_POLL_ENABLED:
        return []

    events = []
    for path in _iter_direct_log_files():
        try:
            current_size = path.stat().st_size
            if str(path) not in offsets:
                # Tail from startup: Filebeat owns historical delivery. This fallback
                # only consumes lines written after Cerebro starts.
                offsets[str(path)] = current_size
                continue
            previous_offset = offsets[str(path)]
            if current_size < previous_offset:
                previous_offset = 0

            with path.open("r", errors="replace") as handle:
                handle.seek(previous_offset)
                lines_read = 0
                while lines_read < max_lines:
                    line = handle.readline()
                    if not line:
                        break
                    lines_read += 1
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    source_type = _source_type_for_direct_log(path)
                    events.append(json.dumps({
                        "log": {"file": {"path": str(path)}},
                        "fields": {"source_type": source_type},
                        "message": line,
                    }))
                offsets[str(path)] = handle.tell()
        except Exception as e:
            print(f"⚠️ No se pudo leer log directo {path}: {e}", flush=True)
    return events

def reset_brain_state():
    return {
        "traffic_monitor": TrafficRateMonitor(),
        "baseline_model": TrafficBaselineModel(),
        "replay_guard": EventReplayGuard(),
        "alert_cooldown": {},
        "last_print_time": time.time(),
        "direct_log_offsets": {},
        "last_direct_poll": 0,
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
    purge_trash_events(es)
    engine = RiskFusionEngine()
    discovered_assets = DiscoveredAssetStore(es, DISCOVERED_ASSETS_INDEX)

    state = reset_brain_state()
    traffic_monitor = state["traffic_monitor"]
    baseline_model = state["baseline_model"]
    replay_guard = state["replay_guard"]
    alert_cooldown = state["alert_cooldown"]
    last_print_time = state["last_print_time"]
    direct_log_offsets = state["direct_log_offsets"]
    last_direct_poll = state["last_direct_poll"]

    while True:
        try:
            # --- NUEVO: CHECK DE COMANDOS DE CONTROL ---
            discovered_assets.periodic_scan()

            # 1. Reset IA
            if r.exists("cmd_reset_brain"):
                print("♻️ COMANDO RECIBIDO: Borrando memoria IA...", flush=True)

                state = reset_brain_state()
                traffic_monitor = state["traffic_monitor"]
                baseline_model = state["baseline_model"]
                replay_guard = state["replay_guard"]
                alert_cooldown = state["alert_cooldown"]
                last_print_time = state["last_print_time"]
                direct_log_offsets = state["direct_log_offsets"]
                last_direct_poll = state["last_direct_poll"]

                r.delete("cmd_reset_brain")
                r.delete(REDIS_KEY)

                print("✅ Memoria IA borrada. Esperando tráfico nuevo...", flush=True)
                time.sleep(1)
                continue

            # 2. Reset Demo Total
            if r.exists("cmd_full_reset_demo"):
                state = full_reset_demo(es, r, engine)

                traffic_monitor = state["traffic_monitor"]
                baseline_model = state["baseline_model"]
                replay_guard = state["replay_guard"]
                alert_cooldown = state["alert_cooldown"]
                last_print_time = state["last_print_time"]
                direct_log_offsets = state["direct_log_offsets"]
                last_direct_poll = state["last_direct_poll"]

                r.delete("cmd_full_reset_demo")

                print("✅ Sistema reiniciado para demo. Estado limpio.", flush=True)
                time.sleep(2)
                continue

            # 3. Forzar re-entrenamiento
            if r.exists("cmd_force_train"):
                print("🎓 COMANDO: Reiniciando línea base de tráfico...", flush=True)
                baseline_model.reset()
                traffic_monitor.reset()
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

            now_poll = time.time()
            if not batch_raw and now_poll - last_direct_poll >= DIRECT_LOG_POLL_INTERVAL:
                direct_events = poll_direct_source_logs(direct_log_offsets)
                if direct_events:
                    print(f"📥 Fallback directo: {len(direct_events)} eventos leídos desde logs de sensores", flush=True)
                    batch_raw.extend(direct_events)
                last_direct_poll = now_poll

            if not batch_raw:
                item_block = r.blpop(REDIS_KEY, timeout=1)
                if item_block: batch_raw.append(item_block[1])
                else: continue

            normalized_events = []
            for raw_json in batch_raw:
                doc = normalizar_evento(raw_json)
                if doc and replay_guard.accept(raw_json):
                    normalized_events.append((raw_json, doc))
            if not normalized_events:
                continue

            docs = [doc for _, doc in normalized_events]
            traffic_metrics = traffic_monitor.observe(docs)
            ai_score = baseline_model.score(traffic_metrics)
            current_eps = traffic_metrics['accepted_eps']
            flood_count = len(traffic_metrics['flood_keys'])

            if time.time() - last_print_time > 2.0:
                if flood_count:
                    icon, status_msg = "🔥", f"FLOOD CONFIRMADO ({flood_count} flujo(s))"
                elif ai_score < -0.10:
                    icon, status_msg = "⚠️", "DESVIACIÓN DE LÍNEA BASE"
                else:
                    icon, status_msg = "🟢", "NORMAL"
                print(
                    f"{icon} [IA MONITOR] Score: {ai_score:.3f} | "
                    f"EPS válidos: {current_eps:.1f} | Flujo máx: {traffic_metrics['max_flow_eps']:.1f} | "
                    f"Estado: {status_msg}",
                    flush=True,
                )
                last_print_time = time.time()

            actions_bulk = []
            for raw_json, doc in normalized_events:
                event_is_flood = traffic_monitor.is_flood(doc, traffic_metrics)
                event_ai_score = -1.0 if event_is_flood else ai_score
                key = (str(doc.get('src_ip')), str(doc.get('dst_ip')), str(doc.get('protocol')))
                detection_reason = traffic_metrics['reasons'].get(key)
                final_doc = engine.evaluar_riesgo(
                    doc,
                    event_ai_score,
                    event_is_flood,
                    detection_reason=detection_reason,
                    traffic_metrics=traffic_metrics,
                )
                discovered_assets.process_event(raw_json, final_doc)

                if final_doc.get('risk_label') == 'CRÍTICO':
                    attacker_ip = final_doc.get('src_ip', 'unknown')
                    now = time.time()
                    if now - alert_cooldown.get(attacker_ip, 0) > 60:
                        subject = f"🚨 {final_doc.get('mitre_msg')}"
                        body = (
                            f"CRÍTICO Detectado\nEPS válidos: {current_eps:.1f}\n"
                            f"IP: {attacker_ip}\nEvidencia: {detection_reason or 'reglas/riesgo'}"
                        )
                        send_email_alert(subject, body, level="CRITICAL")
                        alert_cooldown[attacker_ip] = now

                final_doc.pop("_event_epoch", None)
                actions_bulk.append({"_index": INDEX_NAME, "_source": final_doc})

            if actions_bulk:
                helpers.bulk(es, actions_bulk)

        except Exception as e:
            print(f"🔥 Error: {e}", flush=True); time.sleep(1)

if __name__ == "__main__":
    main()