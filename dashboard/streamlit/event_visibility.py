"""Reglas de visibilidad comunes para todas las vistas de eventos del dashboard."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping

LEGACY_TEST_SID = "1000005"
LEGACY_TEST_MESSAGE = "[TEST] Ping Detectado en WiFi"
UNSPECIFIED_IPV4 = "0.0.0.0"
LEGACY_GLOBAL_FLOOD_MESSAGE = "CRÍTICO: Inundación de Red (DoS)"
UNSPECIFIED_FLOW_RE = re.compile(r"\b0\.0\.0\.0(?::\d+)?\s*(?:-|=)>\s*0\.0\.0\.0(?::\d+)?\b")
_IP_TOKEN_RE = re.compile(r"[0-9A-Fa-f:]+")


def _walk_values(value):
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _walk_values(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _walk_values(item)
    else:
        yield str(value)


def contains_ipv6(value) -> bool:
    for text in _walk_values(value):
        if "IPV6" in text.upper():
            return True
        for token in _IP_TOKEN_RE.findall(text):
            if ":" not in token:
                continue
            try:
                if ipaddress.ip_address(token.strip("[](){}<>,;")).version == 6:
                    return True
            except ValueError:
                continue
    return False


def is_legacy_test_alert(value) -> bool:
    """Reconoce la alerta heredada por SID o mensaje en cualquier campo."""
    for text in _walk_values(value):
        if LEGACY_TEST_MESSAGE.lower() in text.lower():
            return True
        if re.search(rf"\[\s*\d+\s*:\s*{LEGACY_TEST_SID}\s*:\s*\d+\s*\]", text):
            return True
        if re.search(rf"\bsid\s*:\s*{LEGACY_TEST_SID}\s*;", text, re.IGNORECASE):
            return True
    return False


def is_unspecified_traffic(value) -> bool:
    """Detecta tráfico basura con ambos extremos en 0.0.0.0."""
    if isinstance(value, Mapping):
        src_ip = value.get("src_ip")
        dst_ip = value.get("dst_ip")
        if str(src_ip).strip() == UNSPECIFIED_IPV4 and str(dst_ip).strip() == UNSPECIFIED_IPV4:
            return True
    return any(UNSPECIFIED_FLOW_RE.search(text) for text in _walk_values(value))


def is_legacy_unconfirmed_flood(value) -> bool:
    if not isinstance(value, Mapping):
        return False
    message = str(value.get("mitre_msg", ""))
    return message == LEGACY_GLOBAL_FLOOD_MESSAGE and "dos_confirmed" not in value


def is_legacy_icmp_flood(value) -> bool:
    if not isinstance(value, Mapping):
        return False
    text = f"{value.get('message', '')} {value.get('raw_log', '')}".lower()
    is_icmp = str(value.get("protocol", "")).lower() == "icmp" or "sis icmp detectado" in text
    return (
        value.get("dos_confirmed") is True
        and is_icmp
        and "detection_model_version" not in value
    )


def is_visible_event(value) -> bool:
    return (
        not contains_ipv6(value)
        and not is_legacy_test_alert(value)
        and not is_unspecified_traffic(value)
        and not is_legacy_unconfirmed_flood(value)
        and not is_legacy_icmp_flood(value)
    )
