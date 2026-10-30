"""Transformer les logs texte ou JSON en dictionnaires validés."""

import json
from datetime import datetime
from ipaddress import ip_address
from typing import Any, TypedDict


class Log(TypedDict):
    """Types des champs disponibles après parsing."""

    timestamp: datetime
    level: str
    ip: str
    user: str
    event: str
    payload: str | dict[str, Any] | tuple[str, int, str]
    connection: tuple[str, int, str] | None
    source: tuple[str, int]
    message: str


LEVELS = frozenset({"INFO", "WARNING", "ERROR", "CRITICAL"})


