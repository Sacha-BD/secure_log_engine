"""Transformer une ligne de log en dictionnaire Python."""

import json
import math
from datetime import datetime
from ipaddress import ip_address
from typing import Any, TypedDict


class Log(TypedDict):
    """Structure d'un log après sa lecture."""

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


def validate_json(value: Any) -> None:
    """Refuser les nombres non finis et les chaînes Unicode invalides."""
    if isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("nombre JSON non fini")
    elif isinstance(value, dict):
        for key, item in value.items():
            validate_json(key)
            validate_json(item)
    elif isinstance(value, list):
        for item in value:
            validate_json(item)


def parse_log(text: str, source: tuple[str, int] = ("<texte>", 1)) -> Log:
    """Accepter un objet JSON ou six champs séparés par |."""
    text = text.strip()
    if text.startswith("{"):
        record = json.loads(text)
    else:
        parts = text.split("|", 5)
        if len(parts) != 6:
            raise ValueError("six champs séparés par | sont attendus")
        record = dict(zip(
            ("timestamp", "level", "ip", "user", "event", "payload"),
            parts,
        ))
        payload_text = parts[5].strip()
        if payload_text.startswith(("{", "[")):
            record["payload"] = json.loads(payload_text)

    if not isinstance(record, dict):
        raise ValueError("le log doit être un objet JSON")
    # json.loads accepte NaN/Infinity et les surrogates Unicode isolés.
    # Vérifier aussi les champs qui ne servent pas au message normalisé.
    validate_json(record)
    for field in ("timestamp", "level", "ip", "user", "event"):
        if not isinstance(record.get(field), str) or not record[field].strip():
            raise ValueError(f"champ texte absent ou vide : {field}")
    timestamp = datetime.fromisoformat(record["timestamp"].strip())
    # Le format du projet utilise des dates locales sans fuseau.
    if timestamp.tzinfo is not None:
        raise ValueError("horodatage local sans fuseau attendu")
    level = record["level"].strip().upper()
    if level not in LEVELS:
        raise ValueError(f"niveau inconnu : {level!r}")
    address = str(ip_address(record["ip"].strip()))
    payload = record.get("payload", "")
    connection = None
    if isinstance(payload, list):
        if len(payload) != 3:
            raise ValueError("connexion attendue : [IP, port, protocole]")
        host, port, protocol = payload
        if not isinstance(host, str) or type(port) is not int:
            raise ValueError("IP texte et port entier attendus")
        if not 1 <= port <= 65535 or not isinstance(protocol, str):
            raise ValueError("port ou protocole invalide")
        protocol = protocol.strip().upper()
        if protocol not in {"TCP", "UDP"}:
            raise ValueError("protocole attendu : TCP ou UDP")
        connection = (str(ip_address(host)), port, protocol)
        payload = connection
    elif not isinstance(payload, (str, dict)):
        raise ValueError("payload attendu : texte, objet JSON ou connexion")
    return Log(
        timestamp=timestamp,
        level=level,
        ip=address,
        user=record["user"].strip(),
        event=record["event"].strip().upper(),
        payload=payload,
        connection=connection,
        source=source,
        message="",
    )
