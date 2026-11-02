"""Tests unitaires et intégration, sans dépendance externe."""

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from main import BASE_DIR, run
from src.analyzer import Analyzer
from src.audit import export_audit
from src.ingestion import load_blacklist, read_logs, read_multiple_logs
from src.parser import parse_log
from src.processing import describe_payload, process_logs
from src.rules import apply_security_rules, detect_bruteforce


def sample(event="LOGIN_FAILED", ip="192.0.2.1", user="alice"):
    return parse_log(
        f"2026-09-29 10:00:00|error|{ip}|{user}|{event}|test"
    )


class ParsingTests(unittest.TestCase):
    def test_types_and_normalization(self):
        log = sample()
        self.assertIsInstance(log["timestamp"], datetime)
        self.assertIsInstance(log["source"], tuple)
        self.assertEqual(log["level"], "ERROR")

    def test_json_and_connection(self):
        record = {
            "timestamp": "2026-09-29 10:00:00", "level": "info",
            "ip": "2001:db8::1", "user": "alice", "event": "connection",
            "payload": ["192.0.2.2", 443, "tcp"],
        }
        log = parse_log(json.dumps(record))
        self.assertEqual(log["connection"], ("192.0.2.2", 443, "TCP"))
        self.assertEqual(log["payload"], log["connection"])

    def test_bad_fields(self):
        base = "2026-09-29 10:00:00|ERROR|192.0.2.1|alice|TEST|{}"
        bad = [
            "broken", base.replace("2026-09-29", "2026-02-30"),
            base.replace("ERROR", "DEBUG"), base.replace("192.0.2.1", "bad"),
            base.replace("alice", " "), base.replace("{}", "{bad"),
            base.replace("{}", '["192.0.2.2",true,"TCP"]'),
            base.replace("{}", '["192.0.2.2",70000,"TCP"]'),
            base.replace("{}", '["192.0.2.2",80,"ICMP"]'),
        ]
        for text in bad:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_log(text)

    def test_match_three_forms(self):
        self.assertEqual(describe_payload(" texte "), "texte")
        self.assertEqual(
            describe_payload({"level": "ERROR", "code": 401}),
            "Erreur applicative 401",
        )
        self.assertIn("TCP", describe_payload(("192.0.2.1", 443, "TCP")))

    def test_pipeline_is_lazy_and_counts_rejections(self):
        counters = dict(read=0, ignored=0, invalid=0, valid=0)
        lines = [
            ("test", 1, ""), ("test", 2, "# commentaire"),
            ("test", 3, "invalide"),
            ("test", 4, "2026-09-29 10:00:00|INFO|192.0.2.1|a|OK|ok"),
        ]
        stream = process_logs(lines, counters)
        self.assertEqual(counters["read"], 0)
        with self.assertLogs(level="WARNING"):
            self.assertEqual(len(list(stream)), 1)
        self.assertEqual(counters, dict(read=4, ignored=2, invalid=1, valid=1))

    def test_strict_mode(self):
        counters = dict(read=0, ignored=0, invalid=0, valid=0)
        with self.assertRaisesRegex(ValueError, "test:42"):
            list(process_logs([("test", 42, "bad")], counters, True))


class IngestionTests(unittest.TestCase):
    def test_files_are_opened_on_demand(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log"
            stream = read_logs(path)
            path.write_text("premier\ndeuxième\n", encoding="utf-8")
            with self.assertRaises(FileNotFoundError):
                combined = read_multiple_logs([path, path.parent / "absent"])
                self.assertEqual(next(combined)[2], "premier")
                self.assertEqual(next(combined)[2], "deuxième")
                next(combined)
            self.assertEqual(list(stream)[1][1], 2)

    def test_blacklist_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "blacklist"
            path.write_text("192.0.2.1\n192.0.2.1 # doublon\n")
            self.assertEqual(load_blacklist(path), frozenset({"192.0.2.1"}))
            path.write_text("IP invalide\n")
            with self.assertRaises(ValueError):
                load_blacklist(path)


class RuleTests(unittest.TestCase):
    def evaluate(self, events, threshold=3):
        histories = {}
        alerts = []
        for event in events:
            alerts.extend(apply_security_rules(
                detect_bruteforce, log=event, threshold=threshold,
                histories=histories,
            ))
        return alerts, histories

    def test_threshold_and_disjoint_blocks(self):
        self.assertEqual(len(self.evaluate([sample()] * 2)[0]), 0)
        self.assertEqual(len(self.evaluate([sample()] * 3)[0]), 1)
        self.assertEqual(len(self.evaluate([sample()] * 7)[0]), 2)

    def test_success_resets_series(self):
        events = [sample()] * 2 + [sample("LOGIN_SUCCESS")] + [sample()] * 2
        self.assertEqual(self.evaluate(events)[0], [])
        self.assertEqual(len(self.evaluate(events + [sample()])[0]), 1)

    def test_identities_are_independent(self):
        events = [sample(), sample(ip="192.0.2.2"), sample(user="bob")]
        self.assertEqual(self.evaluate(events * 2)[0], [])
        self.assertEqual(len(self.evaluate(events * 3)[0]), 3)

    def test_network_does_not_reset_authentication(self):
        events = [sample(), sample("CONNECTION"), sample(), sample()]
        self.assertEqual(len(self.evaluate(events)[0]), 1)

    def test_threshold_one(self):
        self.assertEqual(len(self.evaluate([sample()], 1)[0]), 1)
        self.assertEqual(self.evaluate([sample("LOGIN_SUCCESS")], 1)[0], [])

    def test_history_is_bounded(self):
        _, histories = self.evaluate([sample()] * 10001, 5)
        self.assertTrue(all(len(h) <= 5 for h in histories.values()))

    def test_rule_functions_and_configuration(self):
        def custom(log, **options):
            return {"value": options["marker"], "user": log["user"]}
        alerts = list(apply_security_rules(custom, log=sample(), marker=42))
        self.assertEqual(alerts, [{"value": 42, "user": "alice"}])
        self.assertEqual(list(apply_security_rules(log=sample())), [])
        with self.assertRaises(ValueError):
            list(apply_security_rules(log=sample(), threshold=0))
        with self.assertRaises(TypeError):
            list(apply_security_rules(42, log=sample()))


class IntegrationTests(unittest.TestCase):
    def test_aggregation_and_sets(self):
        analyzer = Analyzer()
        analyzer.update(sample())
        analyzer.update(sample(ip="192.0.2.2"))
        result = analyzer.summary(frozenset({"192.0.2.2", "192.0.2.3"}))
        self.assertEqual(result["by_level"], {"ERROR": 2})
        self.assertEqual(result["sets"]["intersection"], ["192.0.2.2"])
        self.assertEqual(result["sets"]["difference"], ["192.0.2.1"])
        self.assertEqual(len(result["sets"]["union"]), 3)
        self.assertEqual(
            result["sets"]["symmetric_difference"], ["192.0.2.1", "192.0.2.3"]
        )

    def test_demo_and_exported_alerts(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            with self.assertLogs(level="WARNING"):
                result = run(
                    [BASE_DIR / "data/auth.log",
                     BASE_DIR / "data/network.log"],
                    BASE_DIR / "data/blacklist.txt", out,
                )
            self.assertEqual(result["total"], 22)
            self.assertEqual(result["input"]["invalid"], 3)
            self.assertEqual(result["alerts"], {
                "BRUTE_FORCE": 2, "BLACKLIST": 12, "CRITICAL": 1,
            })
            alerts = [json.loads(line) for line in
                      (out / "alerts.jsonl").read_text().splitlines()]
            self.assertEqual(len(alerts), 15)
            saved = json.loads((out / "summary.json").read_text())
            self.assertEqual(saved, result)
            audit = json.loads((out / "audit.json").read_text())
            self.assertEqual(
                audit["pipeline_locals"]["histories"]["type"], "dict"
            )

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.log"
            path.touch()
            summary = run([path], BASE_DIR / "data/blacklist.txt", path.parent)
            self.assertEqual(summary["total"], 0)
            self.assertEqual(summary["alerts"], {})

    def test_audit_does_not_export_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.json"
            export_audit(path, {"password": "SECRET"}, {"count": 123})
            text = path.read_text()
            self.assertNotIn("SECRET", text)
            self.assertIn("password", text)

    def test_cannot_overwrite_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "alerts.jsonl"
            path.write_text("original")
            with self.assertRaises(ValueError):
                run([path], BASE_DIR / "data/blacklist.txt", path.parent)
            self.assertEqual(path.read_text(), "original")

    def test_strict_failure_preserves_previous_results(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            old = out / "alerts.jsonl"
            old.write_text("ancien résultat")
            with self.assertRaises(ValueError):
                run([BASE_DIR / "data/auth.log"],
                    BASE_DIR / "data/blacklist.txt", out, strict=True)
            self.assertEqual(old.read_text(), "ancien résultat")
            self.assertEqual(list(out.iterdir()), [old])

    def test_cli_errors(self):
        for arguments, expected in [
            (["--threshold", "0"], 2), (["fichier_absent.log"], 1),
            (["--strict"], 1),
        ]:
            with self.subTest(arguments=arguments):
                self.check_cli_error(arguments, expected)

    def check_cli_error(self, arguments, expected):
        with tempfile.TemporaryDirectory() as d:
            result = subprocess.run(
                [sys.executable, str(BASE_DIR / "main.py"),
                 "--output", d, *arguments],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, expected)
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
