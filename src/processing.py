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


def normalize_log(log: Log) -> Log:
    """Enrichir chaque dictionnaire sans conserver les logs précédents."""
    result = log.copy()
    result["message"] = describe_payload(log["payload"])
    return result


def process_logs(
    lines: Iterable[SourceLine],
    counters: dict[str, int],
    strict: bool = False,
) -> Iterator[Log]:
    """Compter les entrées ignorées/rejetées et isoler leurs erreurs."""
    def counted_lines() -> Iterator[SourceLine]:
        for line in lines:
            counters["read"] += 1
            if not line[2].strip() or line[2].lstrip().startswith("#"):
                counters["ignored"] += 1
            yield line

    def safe_parse(line: SourceLine) -> Log | None:
        source, number, text = line
        try:
            parsed = parse_log(text, (source, number))
        except (ValueError, TypeError, RecursionError) as error:
            counters["invalid"] += 1
            if strict:
                raise ValueError(f"{source}:{number} : {error}") from error
            logging.warning(
                "%s:%s : ligne rejetée (%s)", source, number, error
            )
            return None
        counters["valid"] += 1
        return parsed

    nonempty = filter(
        lambda line: bool(line[2].strip())
        and not line[2].lstrip().startswith("#"),
        counted_lines(),
    )
    parsed = map(safe_parse, nonempty)
    valid = filter(lambda log: log is not None, parsed)
    return map(normalize_log, valid)
