"""Règles indépendantes passées comme objets au moteur de sécurité."""

from collections import deque
from collections.abc import Callable, Iterator
from typing import Any

from .parser import Log

Alert = dict[str, Any]
Rule = Callable[..., Alert | None]
History = dict[tuple[str, str], deque[bool]]


def make_alert(log: Log, rule: str, message: str) -> Alert:
    """Conserver la provenance exacte de l'événement déclencheur."""
    return {
        "rule": rule,
        "timestamp": log["timestamp"].isoformat(sep=" "),
        "ip": log["ip"],
        "user": log["user"],
        "source": log["source"],
        "message": message,
    }


