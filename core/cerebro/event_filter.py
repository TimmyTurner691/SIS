"""Filtros de eventos aplicados antes de indexar telemetría en SIS."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping

_IP_TOKEN_RE = re.compile(r"[0-9A-Fa-f:]+")


def is_ipv6_address(value) -> bool:
    """Indica si un valor representa una dirección IPv6 válida."""
    try:
        return ipaddress.ip_address(str(value).strip("[](){}<>,;" )).version == 6
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
