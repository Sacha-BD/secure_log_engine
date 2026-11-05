"""Lire les fichiers de logs ligne par ligne."""

from collections.abc import Iterable, Iterator
from ipaddress import ip_address
from pathlib import Path

# Le tuple contient le fichier, le numéro de ligne et son texte.
SourceLine = tuple[str, int, str]


def read_logs(path: Path) -> Iterator[SourceLine]:
    """Renvoyer les lignes d'un fichier une par une avec yield."""
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, start=1):
            yield (str(path), number, line.rstrip("\n"))


def read_multiple_logs(paths: Iterable[Path]) -> Iterator[SourceLine]:
    """Lire plusieurs fichiers à la suite avec yield from."""
    for path in paths:
        yield from read_logs(path)


def load_blacklist(path: Path) -> frozenset[str]:
    """Lire et vérifier les adresses IP de la blacklist."""
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
