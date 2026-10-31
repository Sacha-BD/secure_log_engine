"""Lire les sources sans charger leur contenu complet en mémoire."""

from collections.abc import Iterable, Iterator
from ipaddress import ip_address
from pathlib import Path

# Un tuple conserve la provenance fixe de chaque ligne.
SourceLine = tuple[str, int, str]


def read_logs(path: Path) -> Iterator[SourceLine]:
    """Produire (fichier, numéro de ligne, texte), à la demande."""
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, start=1):
            yield (str(path), number, line.rstrip("\n"))


def read_multiple_logs(paths: Iterable[Path]) -> Iterator[SourceLine]:
    """Lire chaque fichier successivement, dans l'ordre fourni."""
    for path in paths:
        yield from read_logs(path)


def load_blacklist(path: Path) -> frozenset[str]:
    """Charger uniquement les IP uniques, avec validation IPv4/IPv6."""
    addresses: set[str] = set()
    for source, number, line in read_logs(path):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            addresses.add(str(ip_address(value)))
        except ValueError as error:
            raise ValueError(
                f"{source}:{number} : IP blacklist invalide : {value}"
            ) from error
    return frozenset(addresses)
