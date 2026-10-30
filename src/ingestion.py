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


