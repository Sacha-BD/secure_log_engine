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


