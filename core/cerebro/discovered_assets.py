import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone

DISCOVERED_ASSETS_INDEX = "sis-discovered-assets-v1"

# Tabla mínima para enriquecimiento OUI sin depender de red externa.
OUI_VENDOR_MAP = {
    "00:1B:1B": "Siemens AG",
    "00:0E:8C": "Siemens AG",
    "00:05:1B": "Rockwell Automation",
    "00:00:BC": "Rockwell Automation",
    "00:80:F4": "Schneider Electric",
    "00:10:4B": "Schneider Electric",
    "00:1D:9C": "Moxa Technologies",
    "00:90:E8": "Moxa Technologies",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU/KVM",
}

HOSTNAME_KEYS = (
    "host_name",
    "hostname",
    "host",
    "client_fqdn",
    "server_name",
)

MAC_KEYS = (
    "mac",
    "client_addr",
    "src_mac",
    "dst_mac",
    "orig_l2_addr",
    "resp_l2_addr",
)

OT_PORTS = {102, 502, 20000, 2404, 44818, 47808}
MANAGEMENT_PORTS = {22, 23, 80, 443, 445, 3389, 5900, 8080, 8443}


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def is_valid_ip(value):
    try:
        ipaddress.ip_address(str(value))
        return str(value) not in {"0.0.0.0", "::", "255.255.255.255"}
    except ValueError:
        return False


def normalize_mac(value):
    if not value:
        return None
    value = str(value).strip().upper().replace("-", ":")
    compact = value.replace(":", "")
    if len(compact) == 12 and re.fullmatch(r"[0-9A-F]{12}", compact):
        return ":".join(compact[i:i + 2] for i in range(0, 12, 2))
    if re.fullmatch(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", value):
        return value
    return None


def vendor_from_mac(mac):
    if not mac or str(mac).upper() == "N/A":
        return "Desconocido"
    return OUI_VENDOR_MAP.get(mac[:8], "OUI no registrado")


def asset_id_for_ip(ip):
    return hashlib.sha1(str(ip).encode("utf-8")).hexdigest()


def _nested_get(data, path, default=None):
    current = data
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return current if current is not None else default


def _first_present(data, keys):
    for key in keys:
        if key in data and data.get(key):
            return data.get(key)
    return None


def _as_int(value):
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def suggest_criticality(protocols, ports):
    protocols_l = {str(p).lower() for p in protocols if p}
    ports_i = {_as_int(p) for p in ports}
    ports_i.discard(None)

    if protocols_l.intersection({"iec104", "modbus", "s7", "dnp3"}) or ports_i.intersection(OT_PORTS):
        return "CRITICAL"
    if ports_i.intersection({445, 3389, 5900, 23}):
        return "HIGH"
    if ports_i.intersection(MANAGEMENT_PORTS):
        return "MEDIUM"
    return "LOW"


def estimate_os(protocols, ports, hostname=None, vendor=None):
    ports_i = {_as_int(p) for p in ports}
    ports_i.discard(None)
    protocols_l = {str(p).lower() for p in protocols if p}
    vendor_l = str(vendor or "").lower()
    hostname_l = str(hostname or "").lower()

    if protocols_l.intersection({"iec104", "modbus", "s7", "dnp3"}) or ports_i.intersection(OT_PORTS):
        return "OT/PLC probable"
    if ports_i.intersection({445, 3389}) or "win" in hostname_l:
        return "Windows probable"
    if 22 in ports_i and not ports_i.intersection({445, 3389}):
        return "Linux/Unix probable"
    if ports_i.intersection({80, 443, 8080, 8443}):
        return "Dispositivo con servicio web"
    if any(token in vendor_l for token in ["vmware", "qemu", "virtualbox"]):
        return "Host virtualizado probable"
    return "Sin evidencia suficiente"


def parse_zeek_payload(raw_json):
    try:
        event = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
    except (TypeError, ValueError):
        return {}, ""

    file_path = event.get("log", {}).get("file", {}).get("path", "")
    message_raw = event.get("message", {})
    if isinstance(message_raw, str):
        try:
            return json.loads(message_raw), file_path
        except (TypeError, ValueError):
            return {}, file_path
    if isinstance(message_raw, dict):
        return message_raw, file_path
    return {}, file_path


def observations_from_event(raw_json, normalized_doc):
    zeek_data, file_path = parse_zeek_payload(raw_json)
    source = normalized_doc.get("source", "unknown")
    protocol = normalized_doc.get("protocol") or zeek_data.get("proto") or "unknown"
    timestamp = normalized_doc.get("@timestamp") or utc_now_iso()
    observations = []

    src_ip = normalized_doc.get("src_ip") or zeek_data.get("id.orig_h") or _nested_get(zeek_data, ["id", "orig_h"])
    dst_ip = normalized_doc.get("dst_ip") or zeek_data.get("id.resp_h") or _nested_get(zeek_data, ["id", "resp_h"])
    src_port = _as_int(normalized_doc.get("src_port") or zeek_data.get("id.orig_p") or _nested_get(zeek_data, ["id", "orig_p"]))
    dst_port = _as_int(normalized_doc.get("dst_port") or zeek_data.get("id.resp_p") or _nested_get(zeek_data, ["id", "resp_p"]))

    hostname = _first_present(zeek_data, HOSTNAME_KEYS)
    src_mac = normalize_mac(zeek_data.get("orig_l2_addr") or zeek_data.get("src_mac") or zeek_data.get("client_addr"))
    dst_mac = normalize_mac(zeek_data.get("resp_l2_addr") or zeek_data.get("dst_mac") or zeek_data.get("mac"))

    if is_valid_ip(src_ip):
        observations.append({
            "ip": str(src_ip),
            "mac": src_mac,
            "hostname": hostname if source == "zeek" else None,
            "protocols": [protocol],
            "ports": [src_port] if src_port else [],
            "last_seen": timestamp,
            "sources": [source],
        })

    if is_valid_ip(dst_ip):
        observations.append({
            "ip": str(dst_ip),
            "mac": dst_mac,
            "hostname": None,
            "protocols": [protocol],
            "ports": [dst_port] if dst_port else [],
            "last_seen": timestamp,
            "sources": [source],
        })

    # Logs DHCP/ARP pueden traer IP/MAC fuera de id.orig/id.resp.
    extra_ip = zeek_data.get("assigned_ip") or zeek_data.get("requested_ip") or zeek_data.get("client_addr")
    extra_mac = normalize_mac(_first_present(zeek_data, MAC_KEYS))
    if is_valid_ip(extra_ip):
        observations.append({
            "ip": str(extra_ip),
            "mac": extra_mac,
            "hostname": hostname,
            "protocols": [protocol],
            "ports": [],
            "last_seen": timestamp,
            "sources": [source],
        })

    return observations


def merge_asset(existing, observation):
    now = observation.get("last_seen") or utc_now_iso()
    protocols = sorted(set(existing.get("protocolos_vistos", [])) | set(filter(None, observation.get("protocols", []))))
    ports = sorted({_as_int(p) for p in existing.get("puertos_observados", []) + observation.get("ports", []) if _as_int(p) is not None})
    mac = observation.get("mac") or existing.get("mac")
    hostname = observation.get("hostname") or existing.get("hostname")
    vendor = vendor_from_mac(mac)

    asset = {
        "ip": observation["ip"],
        "mac": mac or "N/A",
        "hostname": hostname or "N/A",
        "vendor_oui": vendor,
        "protocolos_vistos": protocols,
        "puertos_observados": ports,
        "primera_vez_visto": existing.get("primera_vez_visto") or now,
        "ultima_vez_visto": max(str(existing.get("ultima_vez_visto") or now), str(now)),
        "criticidad_sugerida": suggest_criticality(protocols, ports),
        "so_estimado": estimate_os(protocols, ports, hostname, vendor),
        "fuentes": sorted(set(existing.get("fuentes", [])) | set(filter(None, observation.get("sources", [])))),
        "event_count": int(existing.get("event_count", 0)) + 1,
        "asset_id": asset_id_for_ip(observation["ip"]),
    }
    return asset


class DiscoveredAssetStore:
    def __init__(self, es, index_name=DISCOVERED_ASSETS_INDEX):
        self.es = es
        self.index_name = index_name
        self.ensure_index()

    def ensure_index(self):
        try:
            if self.es.indices.exists(index=self.index_name):
                return
            self.es.indices.create(index=self.index_name, body={
                "mappings": {
                    "properties": {
                        "ip": {"type": "ip"},
                        "mac": {"type": "keyword"},
                        "hostname": {"type": "keyword"},
                        "vendor_oui": {"type": "keyword"},
                        "protocolos_vistos": {"type": "keyword"},
                        "puertos_observados": {"type": "integer"},
                        "primera_vez_visto": {"type": "date"},
                        "ultima_vez_visto": {"type": "date"},
                        "criticidad_sugerida": {"type": "keyword"},
                        "so_estimado": {"type": "keyword"},
                        "fuentes": {"type": "keyword"},
                        "event_count": {"type": "integer"},
                    }
                }
            }, ignore=400)
        except Exception as e:
            print(f"⚠️ No se pudo asegurar índice de activos descubiertos: {e}", flush=True)

    def upsert_observation(self, observation):
        if not observation or not is_valid_ip(observation.get("ip")):
            return None
        doc_id = asset_id_for_ip(observation["ip"])
        existing = {}
        try:
            res = self.es.get(index=self.index_name, id=doc_id, ignore=[404])
            if res and res.get("found"):
                existing = res.get("_source", {})
        except Exception:
            existing = {}

        asset = merge_asset(existing, observation)
        self.es.index(index=self.index_name, id=doc_id, body=asset)
        return asset

    def process_event(self, raw_json, normalized_doc):
        updated = []
        for observation in observations_from_event(raw_json, normalized_doc):
            try:
                asset = self.upsert_observation(observation)
                if asset:
                    updated.append(asset)
            except Exception as e:
                print(f"⚠️ Error actualizando activo descubierto {observation.get('ip')}: {e}", flush=True)
        return updated
