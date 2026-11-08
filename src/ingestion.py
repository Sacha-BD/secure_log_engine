"""Lire les fichiers de logs ligne par ligne."""

from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import TextIO

from .addresses import normalize_ip

# Le tuple contient le fichier, le numéro de ligne et son texte.
SourceLine = tuple[str, int, str]
STDIN_PATH = Path("-")


def read_stream(stream: Iterable[str], source: str) -> Iterator[SourceLine]:
    """Associer chaque ligne à sa source et à son numéro."""
    for number, line in enumerate(stream, start=1):
        yield source, number, line.rstrip("\n")


def read_logs(path: Path) -> Iterator[SourceLine]:
    """Renvoyer les lignes d'un fichier une par une avec yield."""
    with path.open(encoding="utf-8", errors="surrogateescape") as stream:
        yield from read_stream(stream, str(path))


def read_multiple_logs(
    paths: Iterable[Path], *, stdin: TextIO | None = None,
) -> Iterator[SourceLine]:
    """Lire les fichiers et l'entrée standard dans l'ordre fourni."""
    for path in paths:
        if path == STDIN_PATH and stdin is not None:
            yield from read_stream(stdin, "<stdin>")
        else:
            yield from read_logs(path)


def load_blacklist(path: Path) -> frozenset[str]:
    """Lire et vérifier les adresses IP de la blacklist."""
    addresses: set[str] = set()
    for source, number, line in read_logs(path):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            value.encode("utf-8")
            addresses.add(normalize_ip(value))
        except ValueError as error:
            raise ValueError(
                f"{source}:{number} : IP blacklist invalide : {value!r}"
            ) from error
    return frozenset(addresses)
