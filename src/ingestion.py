"""Lire les sources sans charger leur contenu complet en mémoire."""

from collections.abc import Iterable, Iterator
from ipaddress import ip_address
from pathlib import Path

# Un tuple conserve la provenance fixe de chaque ligne.
SourceLine = tuple[str, int, str]


