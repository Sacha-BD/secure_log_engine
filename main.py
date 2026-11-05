"""Point d'entrée du projet SecureLog Engine."""

import argparse
import json
import logging
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 ou une version plus récente est nécessaire.")

from src.analyzer import Analyzer
from src.audit import export_audit
from src.ingestion import load_blacklist, read_multiple_logs
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
) -> dict:
    """Lancer toutes les étapes de l'analyse."""
    if type(threshold) is not int or threshold < 1:
        raise ValueError("le seuil doit être un entier strictement positif")
    if not paths:
        raise ValueError("au moins un fichier de logs est nécessaire")
    # On vérifie les fichiers avant de commencer l'analyse.
    inputs = [*paths, blacklist_path]
    for path in inputs:
        if not path.is_file():
            raise FileNotFoundError(f"fichier introuvable : {path}")
    targets = [output_dir / name for name in (
        "summary.json", "alerts.jsonl", "audit.json"
    )]
    if {p.resolve() for p in inputs} & {p.resolve() for p in targets}:
        raise ValueError("un fichier de sortie ne peut pas être une entrée")
    blacklist = load_blacklist(blacklist_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    counters = dict(read=0, ignored=0, invalid=0, valid=0)
    analyzer = Analyzer()
    histories: History = {}
    alerts_by_rule: defaultdict[str, int] = defaultdict(int)
    logs = process_logs(read_multiple_logs(paths), counters, strict)
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
                    stream.write(json.dumps(alert, ensure_ascii=False) + "\n")
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
        help="fichiers lus dans cet ordre (défaut : données de démonstration)",
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
        help="nombre d'échecs consécutifs déclenchant une alerte (défaut : 5)",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="arrêter l'analyse dès la première ligne invalide",
    )
    options = parser.parse_args()
    paths = options.files or [
        BASE_DIR / "data/auth.log", BASE_DIR / "data/network.log"
    ]
    logging.basicConfig(
        level=logging.WARNING, format="%(levelname)s : %(message)s"
    )
    try:
        summary = run(
            paths, options.blacklist, options.output,
            options.threshold, options.strict,
        )
    except (OSError, ValueError, UnicodeError) as error:
        print(f"Erreur : {error}", file=sys.stderr)
        return 1
    print("SECURELOG ENGINE")
    print(f"Logs analysés : {summary['total']}")
    print(f"Lignes rejetées : {summary['input']['invalid']}")
    print(f"Par niveau : {summary['by_level']}")
    print(f"Alertes : {summary['alerts']}")
    print(f"Résultats : {options.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
