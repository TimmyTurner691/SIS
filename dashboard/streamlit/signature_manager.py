import json
import os
import re
import signal
from datetime import datetime, timezone
from pathlib import Path

CATALOG_FILE = Path(os.getenv("SIS_SIGNATURE_CATALOG_PATH", "/signature-rules/signature_catalog.json"))
STATE_FILE = Path(os.getenv("SIS_SIGNATURE_STATE_PATH", "/signature-rules/enabled_packages.json"))
ACTIVE_RULES_FILE = Path(os.getenv("SIS_SIGNATURE_ACTIVE_RULES_PATH", "/signature-rules/snort_rules/active.rules"))
SENSOR_RELOAD_FILE = Path(os.getenv("SIS_SIGNATURE_RELOAD_PATH", "/signature-rules/reload_request.json"))

DEFAULT_ENABLED_PACKAGES = ["iec104", "modbus", "web", "dns", "otros"]
RULE_SID_RE = re.compile(r"\bsid\s*:\s*(\d+)\s*;", re.IGNORECASE)
RULE_PREFIXES = ("alert ", "log ", "pass ", "activate ", "dynamic ", "drop ", "reject ", "sdrop ")


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def load_catalog():
    with CATALOG_FILE.open("r", encoding="utf-8") as fh:
        catalog = json.load(fh)
    catalog.setdefault("packages", [])
    catalog.setdefault("profiles", [])
    return catalog


def package_index(catalog=None):
    catalog = catalog or load_catalog()
    return {pkg["id"]: pkg for pkg in catalog.get("packages", [])}


def load_state():
    if not STATE_FILE.exists():
        return {
            "enabled_packages": DEFAULT_ENABLED_PACKAGES,
            "last_profile": "mixto_liviano",
            "updated_at": _now_iso(),
            "updated_by": "system-default",
        }
    with STATE_FILE.open("r", encoding="utf-8") as fh:
        state = json.load(fh)
    state.setdefault("enabled_packages", DEFAULT_ENABLED_PACKAGES)
    return state


def save_state(enabled_packages, profile_id=None, updated_by="dashboard"):
    enabled = sorted(set(enabled_packages))
    state = {
        "enabled_packages": enabled,
        "last_profile": profile_id,
        "updated_at": _now_iso(),
        "updated_by": updated_by,
    }
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with STATE_FILE.open("w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, ensure_ascii=False)
    return state


def profile_packages(profile_id, catalog=None):
    catalog = catalog or load_catalog()
    for profile in catalog.get("profiles", []):
        if profile.get("id") == profile_id:
            return profile.get("packages", [])
    return []


def build_effective_rules(enabled_packages, catalog=None):
    catalog = catalog or load_catalog()
    packages = package_index(catalog)
    chunks = [
        "# SIS active.rules generado automáticamente",
        f"# updated_at: {_now_iso()}",
        f"# enabled_packages: {', '.join(sorted(enabled_packages)) or 'none'}",
        "",
    ]

    for package_id in sorted(set(enabled_packages)):
        pkg = packages.get(package_id)
        if not pkg:
            continue
        chunks.append(f"# --- Paquete: {pkg.get('name', package_id)} ({package_id}) ---")
        for rule in pkg.get("rules", []):
            chunks.append(rule.strip())
        chunks.append("")
    return "\n".join(chunks).rstrip() + "\n"


def validate_rules(rules_text):
    errors = []
    warnings = []
    sids = set()

    for line_no, raw_line in enumerate(rules_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.lower().startswith(RULE_PREFIXES):
            errors.append(f"Línea {line_no}: acción Snort no soportada o formato inválido")
        if "(" not in line or not line.endswith(")"):
            errors.append(f"Línea {line_no}: la regla debe contener opciones entre paréntesis")
        sid_match = RULE_SID_RE.search(line)
        if not sid_match:
            errors.append(f"Línea {line_no}: falta sid")
            continue
        sid = sid_match.group(1)
        if sid in sids:
            errors.append(f"Línea {line_no}: sid duplicado {sid}")
        sids.add(sid)

    if not sids:
        warnings.append("No hay reglas activas; Snort quedará sin firmas de detección SIS.")

    return {"valid": not errors, "errors": errors, "warnings": warnings, "rule_count": len(sids)}


def apply_packages(enabled_packages, profile_id=None, updated_by="dashboard"):
    catalog = load_catalog()
    known_packages = set(package_index(catalog).keys())
    unknown = sorted(set(enabled_packages) - known_packages)
    if unknown:
        return {"ok": False, "validation": {"valid": False, "errors": [f"Paquetes desconocidos: {', '.join(unknown)}"], "warnings": [], "rule_count": 0}}

    rules_text = build_effective_rules(enabled_packages, catalog)
    validation = validate_rules(rules_text)
    if not validation["valid"]:
        return {"ok": False, "validation": validation}

    ACTIVE_RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    ACTIVE_RULES_FILE.write_text(rules_text, encoding="utf-8")
    state = save_state(enabled_packages, profile_id=profile_id, updated_by=updated_by)
    request_sensor_reload(validation["rule_count"])
    return {"ok": True, "state": state, "validation": validation, "active_rules_path": str(ACTIVE_RULES_FILE)}


def request_sensor_reload(rule_count):
    SENSOR_RELOAD_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {"requested_at": _now_iso(), "active_rules": str(ACTIVE_RULES_FILE), "rule_count": rule_count}
    SENSOR_RELOAD_FILE.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    pid_file = Path(os.getenv("SIS_SNORT_PID_FILE", "/sensor-health/snort.pid"))
    if pid_file.exists():
        try:
            os.kill(int(pid_file.read_text().strip()), signal.SIGHUP)
            payload["signal"] = "SIGHUP"
        except (OSError, ValueError):
            payload["signal"] = "pending-watchdog"
    return payload
