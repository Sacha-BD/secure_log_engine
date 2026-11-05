"""Point d'entrée du projet SecureLog Engine."""

import argparse
import json
import logging
import sys
import tempfile
from collections import defaultdict
from io import TextIOWrapper
from pathlib import Path
from typing import Any, TextIO

from src.analyzer import Analyzer
from src.audit import export_audit
from src.ingestion import STDIN_PATH, load_blacklist, read_multiple_logs
from src.processing import process_logs
from src.rules import (
    History,
    apply_security_rules,
    detect_blacklisted_ip,
    detect_bruteforce,
    detect_critical_event,
)

BASE_DIR = Path(__file__).resolve().parent


def positive_int(text: str) -> int:
    """Vérifier que le seuil donné dans la commande est positif."""
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(
            "valeur strictement positive attendue"
        )
    return value


def run(
    paths: list[Path],
    blacklist_path: Path,
    output_dir: Path,
    threshold: int = 5,
    strict: bool = False,
    *,
    stdin: TextIO | None = None,
    alert_output: TextIO | None = None,
) -> dict[str, Any]:
    """Lancer toutes les étapes de l'analyse."""
    if type(threshold) is not int or threshold < 1:
        raise ValueError("le seuil doit être un entier strictement positif")
    if not paths:
        raise ValueError("au moins un fichier de logs est nécessaire")
    file_paths = paths
    if stdin is not None:
        if paths.count(STDIN_PATH) > 1:
            raise ValueError("l'entrée standard ne peut être lue qu'une fois")
        file_paths = [path for path in paths if path != STDIN_PATH]
    inputs = [*file_paths, blacklist_path]
    for path in inputs:
        if not path.is_file():
            raise FileNotFoundError(f"fichier introuvable : {path}")
    targets = [output_dir / name for name in (
        "summary.json", "alerts.jsonl", "audit.json"
    )]
    if {p.resolve() for p in inputs} & {p.resolve() for p in targets}:
        raise ValueError("un fichier de sortie ne peut pas être une entrée")
    for target in targets:
        if target.is_dir():
            raise IsADirectoryError(f"la sortie est un dossier : {target}")
    blacklist = load_blacklist(blacklist_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    counters = dict(read=0, ignored=0, invalid=0, valid=0)
    analyzer = Analyzer()
    histories: History = {}
    alerts_by_rule: defaultdict[str, int] = defaultdict(int)
    sources = read_multiple_logs(paths, stdin=stdin)
    logs = process_logs(sources, counters, strict)
    # Les nouveaux résultats sont d'abord écrits dans un dossier temporaire.
    with tempfile.TemporaryDirectory(dir=output_dir) as temporary:
        staging = Path(temporary)
        # Chaque alerte est écrite dès qu'elle est détectée.
        with (staging / "alerts.jsonl").open("w", encoding="utf-8") as stream:
            for log in logs:
                analyzer.update(log)
                for alert in apply_security_rules(
                    detect_bruteforce,
                    detect_blacklisted_ip,
                    detect_critical_event,
                    log=log,
                    threshold=threshold,
                    histories=histories,
                    blacklist=blacklist,
                ):
                    alerts_by_rule[alert["rule"]] += 1
                    line = json.dumps(alert, ensure_ascii=False) + "\n"
                    stream.write(line)
                    if alert_output is not None:
                        alert_output.write(line)
                        alert_output.flush()
        summary = analyzer.summary(blacklist)
        summary["input"] = counters
        summary["alerts"] = dict(sorted(alerts_by_rule.items()))
        summary["config"] = {"threshold": threshold, "strict": strict}
        (staging / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        export_audit(staging / "audit.json", globals(), locals())
        for target in targets:
            (staging / target.name).replace(target)
    return summary


def main() -> int:
    """Lire les options de la commande puis afficher le résultat."""
    parser = argparse.ArgumentParser(
        description="Analyse progressive de logs système et réseau."
    )
    parser.add_argument(
        "files", nargs="*", type=Path,
        help="fichiers dans l'ordre, ou - pour lire l'entrée standard",
    )
    parser.add_argument(
        "--blacklist", type=Path, default=BASE_DIR / "data/blacklist.txt",
        help="fichier contenant une IP par ligne",
    )
    parser.add_argument(
        "--output", type=Path, default=BASE_DIR / "results",
        help="dossier des résultats (défaut : results/)",
    )
    parser.add_argument(
        "--threshold", type=positive_int, default=5,
        help="seuil d'échecs de connexion consécutifs (défaut : 5)",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="arrêter l'analyse dès la première ligne invalide",
    )
    parser.add_argument(
        "--stream-alerts", action="store_true",
        help="émettre les alertes JSONL sur la sortie standard dès détection",
    )
    arguments = sys.argv[1:]
    separator = arguments.index("--") if "--" in arguments else len(arguments)
    options = parser.parse_intermixed_args(arguments[:separator])
    paths = options.files + [Path(name) for name in arguments[separator + 1:]]
    if not paths:
        paths = [BASE_DIR / "data/auth.log", BASE_DIR / "data/network.log"]
    logging.basicConfig(
        level=logging.WARNING, format="%(levelname)s : %(message)s"
    )
    try:
        stdin = None
        if STDIN_PATH in paths:
            stdin = sys.stdin
            if isinstance(stdin, TextIOWrapper):
                stdin.reconfigure(encoding="utf-8", errors="surrogateescape")
        if options.stream_alerts and isinstance(sys.stdout, TextIOWrapper):
            sys.stdout.reconfigure(encoding="utf-8")
        summary = run(
            paths, options.blacklist, options.output,
            options.threshold, options.strict, stdin=stdin,
            alert_output=sys.stdout if options.stream_alerts else None,
        )
    except (OSError, ValueError) as error:
        print(f"Erreur : {error}", file=sys.stderr)
        return 1
    console = sys.stderr if options.stream_alerts else sys.stdout
    print("SECURELOG ENGINE", file=console)
    print(f"Logs analysés : {summary['total']}", file=console)
    print(f"Lignes rejetées : {summary['input']['invalid']}", file=console)
    print(f"Par niveau : {summary['by_level']}", file=console)
    print(f"Alertes : {summary['alerts']}", file=console)
    print(f"Résultats : {options.output.resolve()}", file=console)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
