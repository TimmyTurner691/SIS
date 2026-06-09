"""Reglas de visibilidad comunes para todas las vistas de eventos del dashboard."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping

LEGACY_TEST_SID = "1000005"
LEGACY_TEST_MESSAGE = "[TEST] Ping Detectado en WiFi"
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


def is_visible_event(value) -> bool:
    return not contains_ipv6(value) and not is_legacy_test_alert(value)
