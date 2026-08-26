"""Filtros de eventos aplicados antes de indexar telemetría en SIS."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping

_IP_TOKEN_RE = re.compile(r"[0-9A-Fa-f:]+")
LEGACY_TEST_SID = "1000005"
LEGACY_TEST_MESSAGE = "[TEST] Ping Detectado en WiFi"
UNSPECIFIED_IPV4 = "0.0.0.0"
UNSPECIFIED_FLOW_RE = re.compile(r"\b0\.0\.0\.0(?::\d+)?\s*(?:-|=)>\s*0\.0\.0\.0(?::\d+)?\b")


def is_ipv6_address(value) -> bool:
    """Indica si un valor representa una dirección IPv6 válida."""
    try:
        return ipaddress.ip_address(str(value).strip("[](){}<>,;")).version == 6
    except ValueError:
        return False


def contains_ipv6(value) -> bool:
    """Detecta IPv6 en estructuras Zeek o en líneas textuales de Snort."""
    if isinstance(value, Mapping):
        return any(contains_ipv6(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(contains_ipv6(item) for item in value)

    text = str(value)
    if "IPV6" in text.upper():
        return True
    for token in _IP_TOKEN_RE.findall(text):
        if ":" in token and is_ipv6_address(token):
            return True
    return False


def is_legacy_test_alert(value) -> bool:
    """Detecta la antigua alerta ICMP de prueba por mensaje o SID Snort."""
    if isinstance(value, Mapping):
        return any(is_legacy_test_alert(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(is_legacy_test_alert(item) for item in value)

    text = str(value)
    if LEGACY_TEST_MESSAGE.lower() in text.lower():
        return True
    if re.search(rf"\[\s*\d+\s*:\s*{LEGACY_TEST_SID}\s*:\s*\d+\s*\]", text):
        return True
    return bool(re.search(rf"\bsid\s*:\s*{LEGACY_TEST_SID}\s*;", text, re.IGNORECASE))


def is_unspecified_traffic(value) -> bool:
    """Detecta eventos sin extremos: 0.0.0.0 como origen y destino."""
    if isinstance(value, Mapping):
        src_ip = value.get("src_ip")
        dst_ip = value.get("dst_ip")
        if str(src_ip).strip() == UNSPECIFIED_IPV4 and str(dst_ip).strip() == UNSPECIFIED_IPV4:
            return True
        return any(is_unspecified_traffic(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(is_unspecified_traffic(item) for item in value)
    return bool(UNSPECIFIED_FLOW_RE.search(str(value)))


def is_loopback_or_test_traffic(value) -> bool:
    """Reject loopback endpoints and synthetic/test telemetry in any event field."""
    if isinstance(value, Mapping):
        for field in ("src_ip", "dst_ip", "id.orig_h", "id.resp_h"):
            candidate = value.get(field)
            if candidate:
                try:
                    if ipaddress.ip_address(str(candidate).strip()).is_loopback:
                        return True
                except ValueError:
                    pass
        return any(is_loopback_or_test_traffic(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(is_loopback_or_test_traffic(item) for item in value)

    text = str(value)
    lowered = text.lower()
    if "localhost" in lowered or "testfr" in lowered or "[test]" in lowered:
        return True
    for token in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,}", text):
        try:
            if ipaddress.ip_address(token.strip("[](){}<>,;")).is_loopback:
                return True
        except ValueError:
            continue
    return False
