"""Mesurer le pipeline : python -m tests.benchmark_memory --lines 10000."""

import argparse
import gc
import json
import platform
import tempfile
import time
import tracemalloc
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any

from main import positive_int, run


def measure(lines: int, distinct: bool = False) -> dict[str, Any]:
    """Mesurer les allocations Python hors génération du fichier d'entrée."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "input.log"
        blacklist = root / "blacklist.txt"
        blacklist.write_text("", encoding="utf-8")
        with source.open("w", encoding="utf-8") as stream:
            for index in range(lines):
                ip = str(IPv4Address(index)) if distinct else "192.0.2.1"
                user = f"user{index}" if distinct else "alice"
                stream.write(
                    f"2026-09-29 10:00:00|ERROR|{ip}|{user}|LOGIN_FAILED|bad\n"
                )
        gc.collect()
        tracemalloc.start()
        started = time.perf_counter()
        try:
            summary = run([source], blacklist, root / "output")
            elapsed = time.perf_counter() - started
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        expected_alerts = 0 if distinct else lines // 5
        if (summary["total"] != lines or summary["input"]["invalid"]
                or summary["alerts"].get("BRUTE_FORCE", 0) != expected_alerts):
            raise RuntimeError("résultats inattendus pendant la mesure")
        return {
            "python": platform.python_version(), "lines": lines,
            "distinct": distinct, "file_bytes": source.stat().st_size,
            "peak_python_bytes": peak, "seconds": round(elapsed, 3),
            "brute_force_alerts": expected_alerts,
        }


def main() -> None:
    """Afficher une mesure JSON par taille de fichier demandée."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lines", nargs="+", type=positive_int, default=[10000, 100000],
    )
    parser.add_argument("--distinct", action="store_true")
    options = parser.parse_args()
    for count in options.lines:
        print(json.dumps(measure(count, options.distinct)), flush=True)


if __name__ == "__main__":
    main()
