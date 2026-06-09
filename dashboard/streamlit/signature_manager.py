"""Gestión del catálogo y del set efectivo de firmas Snort de SIS."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

RULE_RE = re.compile(r"^\s*(alert|log|pass|drop|reject|sdrop)\s+", re.IGNORECASE)
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)\s*;", re.IGNORECASE)
FORBIDDEN_LEGACY_SIDS = {1000005}


class SignatureError(ValueError):
    """Configuración de firmas inválida o imposible de aplicar."""


def default_base_dir() -> Path:
    return Path(os.getenv("SIS_SIGNATURES_DIR", "/signatures"))


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SignatureError(f"No se pudo leer {path.name}: {exc}") from exc


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def validate_rules(text: str) -> list[int]:
    """Valida estructura mínima y SIDs únicos antes de solicitar una recarga."""
    sids: list[int] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not RULE_RE.match(line):
            raise SignatureError(f"Línea {line_number}: acción de regla no reconocida")
        if not line.endswith(")") or "(" not in line:
            raise SignatureError(f"Línea {line_number}: regla incompleta")
        sid_match = SID_RE.search(line)
        if not sid_match:
            raise SignatureError(f"Línea {line_number}: falta SID")
        sid = int(sid_match.group(1))
        if sid in FORBIDDEN_LEGACY_SIDS:
            raise SignatureError(f"SID heredado no permitido: {sid}")
        if sid in sids:
            raise SignatureError(f"SID duplicado: {sid}")
        sids.append(sid)
    return sids


class SignatureManager:
    def __init__(self, base_dir: str | Path | None = None):
        self.base_dir = Path(base_dir) if base_dir else default_base_dir()
        self.catalog_path = self.base_dir / "catalog.json"
        self.profiles_path = self.base_dir / "profiles.json"
        self.state_path = self.base_dir / "state.json"
        self.packages_dir = self.base_dir / "snort_rules" / "packages"
        self.control_dir = self.base_dir / "control"
        self.effective_path = self.control_dir / "effective.rules"
        self.reload_path = self.control_dir / "reload.request"

    def catalog(self) -> list[dict]:
        packages = _read_json(self.catalog_path).get("packages", [])
        ids = [package.get("id") for package in packages]
        if len(ids) != len(set(ids)) or not all(ids):
            raise SignatureError("El catálogo contiene identificadores inválidos o duplicados")
        return packages

    def profiles(self) -> list[dict]:
        return _read_json(self.profiles_path).get("profiles", [])

    def load_state(self) -> dict:
        state = _read_json(self.state_path)
        configured = state.setdefault("packages", {})
        for package in self.catalog():
            configured.setdefault(
                package["id"],
                {"installed": package.get("default_installed", False), "enabled": False},
            )
        return state

    def package_rows(self) -> list[dict]:
        state = self.load_state()
        rows = []
        for package in self.catalog():
            package_state = state["packages"][package["id"]]
            rule_path = self.packages_dir / package["rule_file"]
            rule_count = 0
            if rule_path.exists():
                rule_count = len(validate_rules(rule_path.read_text(encoding="utf-8")))
            rows.append({**package, **package_state, "rule_count": rule_count})
        return rows

    def set_packages(self, installed: Iterable[str], enabled: Iterable[str]) -> dict:
        valid_ids = {package["id"] for package in self.catalog()}
        installed_ids = set(installed)
        enabled_ids = set(enabled)
        unknown = (installed_ids | enabled_ids) - valid_ids
        if unknown:
            raise SignatureError(f"Paquetes desconocidos: {', '.join(sorted(unknown))}")
        if not enabled_ids <= installed_ids:
            raise SignatureError("No se puede habilitar un paquete no instalado")

        state = self.load_state()
        for package_id in valid_ids:
            state["packages"][package_id] = {
                "installed": package_id in installed_ids,
                "enabled": package_id in enabled_ids,
            }
        state["profile"] = None
        self._save_and_apply(state)
        return state

    def apply_profile(self, profile_id: str) -> dict:
        profiles = {profile["id"]: profile for profile in self.profiles()}
        if profile_id not in profiles:
            raise SignatureError(f"Perfil desconocido: {profile_id}")
        state = self.load_state()
        valid_ids = set(state["packages"])
        enabled_ids = set(profiles[profile_id]["enabled_packages"])
        unknown = enabled_ids - valid_ids
        if unknown:
            raise SignatureError(f"El perfil referencia paquetes desconocidos: {', '.join(sorted(unknown))}")
        for package_id, package_state in state["packages"].items():
            if package_id in enabled_ids:
                package_state["installed"] = True
            package_state["enabled"] = package_id in enabled_ids
        state["profile"] = profile_id
        self._save_and_apply(state)
        return state

    def build_effective_rules(self, state: dict | None = None) -> tuple[str, list[str], list[int]]:
        state = state or self.load_state()
        enabled_names = []
        sections = ["# Generado automáticamente por SIS. No editar manualmente."]
        for package in self.catalog():
            package_state = state["packages"].get(package["id"], {})
            if not (package_state.get("installed") and package_state.get("enabled")):
                continue
            rule_path = self.packages_dir / package["rule_file"]
            if not rule_path.is_file():
                raise SignatureError(f"Falta el archivo del paquete {package['name']}: {rule_path.name}")
            enabled_names.append(package["name"])
            sections.extend(["", f"# Paquete: {package['name']}", rule_path.read_text(encoding="utf-8").strip()])
        content = "\n".join(sections).rstrip() + "\n"
        return content, enabled_names, validate_rules(content)

    def _save_and_apply(self, state: dict) -> None:
        content, enabled_names, sids = self.build_effective_rules(state)
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        state["effective_rule_count"] = len(sids)
        state["enabled_package_count"] = len(enabled_names)
        _atomic_write(self.effective_path, content)
        _atomic_write(self.state_path, json.dumps(state, indent=2, ensure_ascii=False) + "\n")
        request = {
            "requested_at": state["updated_at"],
            "enabled_packages": enabled_names,
            "rule_count": len(sids),
        }
        _atomic_write(self.reload_path, json.dumps(request, ensure_ascii=False) + "\n")

    def status(self) -> dict:
        state = self.load_state()
        reload_status_path = self.control_dir / "reload.status.json"
        sensor_status = _read_json(reload_status_path) if reload_status_path.exists() else {}
        return {"state": state, "sensor": sensor_status}
