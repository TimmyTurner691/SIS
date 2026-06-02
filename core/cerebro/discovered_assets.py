import hashlib
import ipaddress
import json
import os
import re
import subprocess
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

DISCOVERED_ASSETS_INDEX = "sis-discovered-assets-v1"
DEFAULT_SWEEP_PREFIX = int(os.getenv("SIS_DISCOVERY_SWEEP_PREFIX", "24"))
NMAP_TIMEOUT_SECONDS = int(os.getenv("SIS_DISCOVERY_NMAP_TIMEOUT", "60"))
ACTIVE_SWEEP_ENABLED = os.getenv("SIS_DISCOVERY_ACTIVE_SWEEP", "true").lower() == "true"

RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)

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


def is_private_ipv4(value):
    """Only usable RFC1918 IPv4 host addresses are valid discovered assets."""
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    if ip.version != 4 or not any(ip in network for network in RFC1918_NETWORKS):
        return False
    last_octet = int(str(ip).split(".")[-1])
    return last_octet not in {0, 255}


def network_for_ip(ip, prefix=DEFAULT_SWEEP_PREFIX):
    try:
        prefix = min(max(int(prefix), 24), 30)
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
    except ValueError:
        return None


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


def vendor_from_mac(mac, fallback_vendor=None):
    if fallback_vendor:
        return str(fallback_vendor)
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


def _list_from(value):
    if isinstance(value, list):
        return value
    if value in (None, "", "N/A"):
        return []
    return [value]


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
    if "nmap_ping_sweep" in protocols_l:
        return "Equipo activo por ping sweep"
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

    if is_private_ipv4(src_ip):
        observations.append({
            "ip": str(src_ip),
            "mac": src_mac,
            "hostname": hostname if source == "zeek" else None,
            "protocols": [protocol],
            "ports": [src_port] if src_port else [],
            "last_seen": timestamp,
            "sources": [source],
        })

    if is_private_ipv4(dst_ip):
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
    if is_private_ipv4(extra_ip):
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
    existing_protocols = _list_from(existing.get("protocolos_vistos"))
    existing_ports = _list_from(existing.get("puertos_observados"))
    protocols = sorted(set(existing_protocols) | set(filter(None, observation.get("protocols", []))))
    ports = sorted({_as_int(p) for p in existing_ports + observation.get("ports", []) if _as_int(p) is not None})
    mac = observation.get("mac") or existing.get("mac")
    hostname = observation.get("hostname") or existing.get("hostname")
    vendor = vendor_from_mac(mac, observation.get("vendor"))

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
        "so_estimado": observation.get("os") or estimate_os(protocols, ports, hostname, vendor),
        "fuentes": sorted(set(_list_from(existing.get("fuentes"))) | set(filter(None, observation.get("sources", [])))),
        "event_count": int(existing.get("event_count", 0)) + 1,
        "asset_id": asset_id_for_ip(observation["ip"]),
    }
    return asset


def parse_nmap_ping_sweep(xml_output):
    observations = []
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return observations

    timestamp = utc_now_iso()
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.attrib.get("state") != "up":
            continue

        ip = None
        mac = None
        vendor = None
        for address in host.findall("address"):
            addrtype = address.attrib.get("addrtype")
            if addrtype == "ipv4":
                ip = address.attrib.get("addr")
            elif addrtype == "mac":
                mac = normalize_mac(address.attrib.get("addr"))
                vendor = address.attrib.get("vendor")

        if not is_private_ipv4(ip):
            continue

        hostname = None
        hostname_el = host.find("hostnames/hostname")
        if hostname_el is not None:
            hostname = hostname_el.attrib.get("name")

        observations.append({
            "ip": str(ip),
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "protocols": ["nmap_ping_sweep"],
            "ports": [],
            "last_seen": timestamp,
            "sources": ["active_discovery"],
            "os": estimate_os(["nmap_ping_sweep"], [], hostname, vendor),
        })

    return observations


class DiscoveredAssetStore:
    def __init__(self, es, index_name=DISCOVERED_ASSETS_INDEX, active_sweep_enabled=ACTIVE_SWEEP_ENABLED):
        self.es = es
        self.index_name = index_name
        self.active_sweep_enabled = active_sweep_enabled
        self._sweep_lock = threading.Lock()
        self._scheduled_networks = set()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sis-discovery")
        self.ensure_index()
        self.purge_non_private_ipv4_assets()

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

    def purge_non_private_ipv4_assets(self):
        try:
            res = self.es.search(index=self.index_name, body={"query": {"match_all": {}}, "size": 10000}, ignore_unavailable=True)
            for hit in res.get("hits", {}).get("hits", []):
                source = hit.get("_source", {})
                if not is_private_ipv4(source.get("ip")):
                    self.es.delete(index=self.index_name, id=hit.get("_id"), ignore=[404])
                    print(f"🧹 Activo descubierto removido por no ser IPv4 privada: {source.get('ip')}", flush=True)
        except Exception as e:
            print(f"⚠️ No se pudo limpiar activos públicos/IPv6: {e}", flush=True)

    def upsert_observation(self, observation):
        if not observation or not is_private_ipv4(observation.get("ip")):
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

    def schedule_active_sweep(self, ip):
        if not is_private_ipv4(ip):
            return
        network = network_for_ip(ip)
        if network:
            self.schedule_network_sweep(network)

    def schedule_network_sweep(self, network, force=False):
        if not self.active_sweep_enabled:
            return False
        try:
            parsed_network = ipaddress.ip_network(network, strict=False)
        except ValueError:
            return False
        if parsed_network.version != 4 or not any(parsed_network.subnet_of(private_net) for private_net in RFC1918_NETWORKS):
            return False

        network = str(parsed_network)
        with self._sweep_lock:
            if not force and network in self._scheduled_networks:
                return False
            self._scheduled_networks.add(network)

        action = "Re-ejecutando" if force else "Ejecutando"
        print(f"🧭 {action} ping sweep nmap no intrusivo sobre {network}...", flush=True)
        self._executor.submit(self._run_nmap_ping_sweep, network)
        return True

    def rescan_discovered_networks(self):
        networks = set()
        try:
            res = self.es.search(
                index=self.index_name,
                body={"query": {"match_all": {}}, "size": 10000, "_source": ["ip"]},
                ignore_unavailable=True,
            )
            for hit in res.get("hits", {}).get("hits", []):
                ip = hit.get("_source", {}).get("ip")
                if is_private_ipv4(ip):
                    network = network_for_ip(ip)
                    if network:
                        networks.add(network)
        except Exception as e:
            print(f"⚠️ No se pudieron obtener redes descubiertas para re-escaneo: {e}", flush=True)
            return 0

        scheduled = 0
        for network in sorted(networks):
            if self.schedule_network_sweep(network, force=True):
                scheduled += 1
        print(f"🔁 Re-escaneo manual solicitado: {scheduled} redes agendadas.", flush=True)
        return scheduled

    def _run_nmap_ping_sweep(self, network):
        command = ["nmap", "-sn", "-PE", "-oX", "-", network]
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=NMAP_TIMEOUT_SECONDS,
            )
        except FileNotFoundError:
            print("⚠️ nmap no está instalado; descubrimiento activo deshabilitado para esta ejecución.", flush=True)
            return
        except subprocess.TimeoutExpired:
            print(f"⚠️ Timeout ejecutando ping sweep nmap sobre {network}", flush=True)
            return

        if result.returncode not in (0, 1):
            print(f"⚠️ nmap terminó con código {result.returncode} para {network}: {result.stderr[:300]}", flush=True)
            return

        count = 0
        for observation in parse_nmap_ping_sweep(result.stdout):
            if self.upsert_observation(observation):
                count += 1
        print(f"✅ Ping sweep completado en {network}: {count} equipos activos registrados/actualizados.", flush=True)

    def process_event(self, raw_json, normalized_doc):
        updated = []
        for observation in observations_from_event(raw_json, normalized_doc):
            try:
                asset = self.upsert_observation(observation)
                if asset:
                    updated.append(asset)
                    self.schedule_active_sweep(asset["ip"])
            except Exception as e:
                print(f"⚠️ Error actualizando activo descubierto {observation.get('ip')}: {e}", flush=True)
        return updated
