"""Pipeline paresseux : filtrage, parsing, puis normalisation."""

import logging
from collections.abc import Iterable, Iterator
from typing import Any

from .ingestion import SourceLine
from .parser import Log, parse_log


def describe_payload(payload: Any) -> str:
    """Router les trois formes prévues via le structural matching."""
    match payload:
        case str() as text:
            return text.strip()
        case {"level": "ERROR", "code": code}:
            return f"Erreur applicative {code}"
        case dict() as data:
            return ", ".join(f"{key}={value}" for key, value in data.items())
        case (str() as host, int() as port, str() as protocol):
            return f"Connexion {protocol} vers {host}:{port}"
        case _:
            raise ValueError("structure de payload non prise en charge")


