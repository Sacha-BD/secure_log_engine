"""Calculer les statistiques pendant la lecture des logs."""

from collections import defaultdict
from typing import Any

from .parser import Log


class Analyzer:
    """Regrouper les compteurs utilisés pendant l'analyse."""

    def __init__(self) -> None:
        self.total = 0
        self.by_level: defaultdict[str, int] = defaultdict(int)
        self.by_user: defaultdict[str, int] = defaultdict(int)
        self.active_ips: set[str] = set()
        self.error_ips: set[str] = set()

    def update(self, log: Log) -> None:
        """Mettre à jour les statistiques avec un nouveau log."""
        self.total += 1
        self.by_level[log["level"]] += 1
        self.by_user[log["user"]] += 1
        self.active_ips.add(log["ip"])
        if log["level"] in {"ERROR", "CRITICAL"}:
            self.error_ips.add(log["ip"])

    def summary(self, blacklist: frozenset[str]) -> dict[str, Any]:
        """Préparer le résumé qui sera écrit dans le fichier JSON."""
        active = self.active_ips
        return {
            "total": self.total,
            "by_level": dict(sorted(self.by_level.items())),
            "by_user": dict(sorted(self.by_user.items())),
            "active_ips": sorted(active),
            "error_ips": sorted(self.error_ips),
            "sets": {
                "union": sorted(active | blacklist),
                "intersection": sorted(active & blacklist),
                "difference": sorted(active - blacklist),
                "symmetric_difference": sorted(active ^ blacklist),
            },
        }
