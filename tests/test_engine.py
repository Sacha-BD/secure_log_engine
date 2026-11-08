"""Tests unitaires et intégration, sans dépendance externe."""

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from io import StringIO
from itertools import product
from pathlib import Path
from queue import Queue
from threading import Thread
from unittest.mock import patch

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

    def test_invalid_json_values_are_rejected_in_all_fields(self):
        base = {
            "timestamp": "2026-09-29 10:00:00", "level": "INFO",
            "ip": "192.0.2.1", "user": "alice", "event": "TEST",
            "payload": {"level": "ERROR", "code": 0},
        }
        values = [float("nan"), float("inf"), float("-inf"), "\ud800"]
        for value in values:
            with self.subTest(value=repr(value)):
                record = {**base, "extra": {"nested": [value]}}
                with self.assertRaises(ValueError):
                    parse_log(json.dumps(record))
                payload = {**base["payload"], "hidden": [value]}
                text = "2026-09-29 10:00:00|INFO|192.0.2.1|u|TEST|"
                with self.assertRaises(ValueError):
                    parse_log(text + json.dumps(payload))
        with self.assertRaises(ValueError):
            parse_log(json.dumps({**base, "event": "\ud800"}))
        with self.assertRaises(ValueError):
            parse_log(json.dumps({**base, "payload": {"\ud800": 1}}))
        with self.assertRaises(ValueError):
            parse_log(json.dumps(base).replace('"code": 0', '"code": 1e999'))

    def test_valid_nested_json_and_unicode_are_preserved(self):
        payload = {"data": [None, True, -2, 1.25, {"texte": "été 😀"}]}
        text = "2026-09-29 10:00:00|INFO|192.0.2.1|u|TEST|"
        log = parse_log(text + json.dumps(payload))
        self.assertEqual(log["payload"], payload)

    def test_bad_json_values_follow_rejection_policy(self):
        prefix = "2026-09-29 10:00:00|INFO|192.0.2.1|u|TEST|"
        bad_payloads = [
            '{"nested":[NaN]}', '{"value":1e999}',
            r'{"level":"ERROR","code":0,"hidden":"\ud800"}',
            '{"code":NaN,"code":0}',
            '{"nested":' + '[' * 2000 + '0' + ']' * 2000 + '}',
        ]
        for payload in bad_payloads:
            with self.subTest(payload=payload[:60]):
                lines = [("test", 1, prefix + payload),
                         ("test", 2, prefix + "valide")]
                counters = dict(read=0, ignored=0, invalid=0, valid=0)
                with self.assertLogs(level="WARNING"):
                    logs = list(process_logs(lines, counters))
                self.assertEqual(len(logs), 1)
                self.assertEqual(counters["invalid"], 1)
                with self.assertRaisesRegex(ValueError, "test:1"):
                    list(process_logs(lines, counters, strict=True))

    def test_duplicate_keys_are_rejected_in_json_records(self):
        with self.assertRaisesRegex(ValueError, "clé JSON répétée"):
            parse_log('{"event":"LOGIN_FAILED","event":"LOGIN_SUCCESS"}')

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

    def test_normalization_error_uses_rejection_policy(self):
        prefix = "2026-09-29 10:00:00|CRITICAL|192.0.2.1|alice|TEST|"
        lines = [
            ("test", 1, prefix + r'{"level":"ERROR","code":"\ud800"}'),
            ("test", 2, prefix + "message valide"),
        ]
        counters = dict(read=0, ignored=0, invalid=0, valid=0)
        with self.assertLogs(level="WARNING"):
            logs = list(process_logs(lines, counters))
        self.assertEqual([log["message"] for log in logs], ["message valide"])
        self.assertEqual(counters, dict(read=2, ignored=0, invalid=1, valid=1))
        with self.assertRaisesRegex(ValueError, "test:1"):
            list(process_logs(lines, counters, strict=True))


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
            path.write_bytes(b"fe80::1%bad\xff\n")
            with self.assertRaisesRegex(ValueError, "blacklist:1"):
                load_blacklist(path)
            path.write_bytes(b"bad\x1b[2J\n")
            with self.assertRaises(ValueError) as error:
                load_blacklist(path)
            self.assertNotIn("\x1b", str(error.exception))


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

    def test_success_releases_pending_history_immediately(self):
        for threshold in (2, 5, sys.maxsize + 1):
            with self.subTest(threshold=threshold):
                alerts, histories = self.evaluate(
                    [sample(), sample("LOGIN_SUCCESS")], threshold,
                )
                self.assertEqual(alerts, [])
                self.assertEqual(histories, {})

    def test_all_short_authentication_sequences(self):
        for threshold in range(1, 6):
            for sequence in product((False, True), repeat=8):
                histories = {}
                consecutive = 0
                for failed in sequence:
                    event = "LOGIN_FAILED" if failed else "LOGIN_SUCCESS"
                    consecutive = consecutive + 1 if failed else 0
                    expected = consecutive == threshold
                    if expected:
                        consecutive = 0
                    alerts = list(apply_security_rules(
                        detect_bruteforce, log=sample(event),
                        threshold=threshold, histories=histories,
                    ))
                    self.assertEqual(bool(alerts), expected)
                    self.assertEqual(
                        sum(map(len, histories.values())), consecutive,
                    )

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
        self.assertEqual(len(histories[("192.0.2.1", "alice")]), 1)

    def test_large_threshold_does_not_allocate_a_full_history(self):
        alerts, histories = self.evaluate([sample()] * 3, sys.maxsize + 1)
        self.assertEqual(alerts, [])
        self.assertEqual(len(histories[("192.0.2.1", "alice")]), 3)

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
            with (out / "alerts.jsonl").open(encoding="utf-8") as stream:
                alerts = [json.loads(line) for line in stream]
            self.assertEqual(len(alerts), 15)
            saved = json.loads((out / "summary.json").read_text())
            self.assertEqual(saved, result)
            audit = json.loads((out / "audit.json").read_text())
            self.assertEqual(
                audit["pipeline_locals"]["histories"]["type"], "dict"
            )

    def test_address_aliases_share_blacklist_and_login_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / "input.log"
            blacklist = root / "blacklist.txt"
            addresses = (
                "192.0.2.1", "::ffff:c000:201", "fe80::1%eth0", "FE80::1",
            )
            logs.write_text("".join(
                f"2026-09-29 10:00:00|ERROR|{ip}|u|LOGIN_FAILED|test\n"
                for ip in addresses
            ), encoding="utf-8")
            blacklist.write_text(
                "::ffff:192.0.2.1\nfe80::1%eth1\n", encoding="utf-8",
            )

            summary = run([logs], blacklist, root, threshold=2)

            self.assertEqual(summary["active_ips"], ["192.0.2.1", "fe80::1"])
            self.assertEqual(summary["alerts"], {
                "BLACKLIST": 4, "BRUTE_FORCE": 2,
            })

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.log"
            path.touch()
            summary = run([path], BASE_DIR / "data/blacklist.txt", path.parent)
            self.assertEqual(summary["total"], 0)
            self.assertEqual(summary["alerts"], {})

    def test_invalid_utf8_does_not_discard_following_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.log"
            path.write_bytes(
                b"bad byte: \xff\n"
                b"2026-09-29 10:00:00|INFO|192.0.2.1|alice|TEST|ok\n"
            )
            blacklist = BASE_DIR / "data/blacklist.txt"
            with self.assertLogs(level="WARNING") as warnings:
                result = run([path], blacklist, path.parent)
            self.assertIn("input.log:1", warnings.output[0])
            self.assertEqual(result["input"], {
                "read": 2, "ignored": 0, "invalid": 1, "valid": 1,
            })
            with self.assertRaisesRegex(ValueError, "input.log:1"):
                run([path], blacklist, path.parent, strict=True)

    def test_cli_combines_stdin_and_files_in_order(self):
        line = "2026-09-29 10:00:00|ERROR|192.0.2.1|alice|LOGIN_FAILED|échec"
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            path = out / "input.log"
            path.write_text(line + "\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(BASE_DIR / "main.py"), str(path),
                 "--output", directory, "--threshold", "2", "--stream-alerts",
                 "-"],
                input=(line + "\n").encode("utf-8"),
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            alert = json.loads((out / "alerts.jsonl").read_text(
                encoding="utf-8"
            ))
            self.assertEqual(json.loads(result.stdout), alert)
            self.assertIn(b"SECURELOG ENGINE", result.stderr)
            self.assertEqual(alert["rule"], "BRUTE_FORCE")
            self.assertEqual(alert["source"], ["<stdin>", 1])

    def test_cli_emits_alert_before_stdin_is_closed(self):
        line = b"2026-09-29 10:00:00|ERROR|192.0.2.1|u|LOGIN_FAILED|bad\n"
        with tempfile.TemporaryDirectory() as directory:
            with subprocess.Popen(
                [sys.executable, str(BASE_DIR / "main.py"),
                 "--output", directory, "--threshold", "2",
                 "--stream-alerts", "-"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as process:
                received = Queue()
                reader = Thread(
                    target=lambda: received.put(process.stdout.readline()),
                    daemon=True,
                )
                reader.start()
                try:
                    process.stdin.write(line * 2)
                    process.stdin.flush()
                    alert = json.loads(received.get(timeout=10))
                    self.assertEqual(alert["rule"], "BRUTE_FORCE")
                    self.assertIsNone(process.poll())
                    self.assertFalse(
                        (Path(directory) / "summary.json").exists()
                    )
                    _, stderr = process.communicate(timeout=10)
                    self.assertEqual(process.returncode, 0, stderr)
                    saved = json.loads(
                        (Path(directory) / "alerts.jsonl").read_bytes()
                    )
                    self.assertEqual(saved, alert)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=10)
                    reader.join(timeout=10)

    def test_invalid_thresholds_and_missing_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            for threshold in (0, -1, True, 1.5, "5"):
                with self.subTest(threshold=threshold):
                    with self.assertRaises(ValueError):
                        run([BASE_DIR / "data/auth.log"],
                            BASE_DIR / "data/blacklist.txt", Path(directory),
                            threshold=threshold)
            with self.assertRaises(ValueError):
                run([], BASE_DIR / "data/blacklist.txt", Path(directory))

    def test_notebook_examples_match_saved_results(self):
        notebook = json.loads(
            (BASE_DIR / "report/rapport.ipynb").read_text(encoding="utf-8")
        )
        source = "\n".join(
            "".join(cell["source"]) for cell in notebook["cells"]
            if cell["cell_type"] == "code"
        )
        expected = "".join(
            "".join(output["text"])
            for cell in notebook["cells"]
            for output in cell.get("outputs", [])
            if output.get("name") == "stdout"
        )
        for cwd in (BASE_DIR, BASE_DIR / "report"):
            with self.subTest(cwd=cwd):
                result = subprocess.run(
                    [sys.executable, "-X", "utf8", "-c", source], cwd=cwd,
                    capture_output=True, encoding="utf-8", timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)

    def test_cli_does_not_print_terminal_control_from_log(self):
        line = b"2026-09-29 10:00:00|INFO\x1b[2J|192.0.2.1|u|TEST|bad\n"
        with tempfile.TemporaryDirectory() as directory:
            for mode, status in (([], 0), (["--strict"], 1)):
                with self.subTest(mode=mode):
                    result = subprocess.run(
                        [sys.executable, str(BASE_DIR / "main.py"),
                         "--output", directory, *mode, "-"],
                        input=line, capture_output=True,
                    )
                    self.assertEqual(result.returncode, status)
                    self.assertIn(b"<stdin>:1", result.stderr)
                    self.assertNotIn(b"\x1b", result.stderr)

    def test_diagnostics_escape_control_characters_in_source_names(self):
        for strict in (False, True):
            with self.subTest(strict=strict):
                lines = [("input\x1b[2J.log", 1, "bad")]
                counters = dict(read=0, ignored=0, invalid=0, valid=0)
                if strict:
                    with self.assertRaises(ValueError) as error:
                        list(process_logs(lines, counters, strict=True))
                    message = str(error.exception)
                else:
                    with self.assertLogs(level="WARNING") as warnings:
                        list(process_logs(lines, counters))
                    message = warnings.output[0]
                self.assertIn(r"\x1b", message)
                self.assertNotIn("\x1b", message)

    def test_cli_treats_arguments_after_double_dash_as_files(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "-empty.log").touch()
            result = subprocess.run(
                [sys.executable, str(BASE_DIR / "main.py"),
                 "--output", directory, "--", "-empty.log"],
                cwd=work, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads((work / "summary.json").read_bytes())
            self.assertEqual(summary["total"], 0)

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

    def test_strict_failure_closes_input_before_propagating_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.log"
            source.touch()
            input_stream = StringIO("invalide\n")
            open_path = Path.open

            def open_tracked(path: Path, *args, **kwargs):
                if path == source:
                    return input_stream
                return open_path(path, *args, **kwargs)

            with patch.object(Path, "open", open_tracked):
                try:
                    run([source], BASE_DIR / "data/blacklist.txt", root,
                        strict=True)
                except ValueError:
                    self.assertTrue(input_stream.closed)
                else:
                    self.fail("Le mode strict devait lever une exception")

    def test_directory_at_output_path_preserves_previous_results(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            summary = out / "summary.json"
            summary.write_text("ancien résultat")
            (out / "alerts.jsonl").mkdir()
            with self.assertRaises(IsADirectoryError):
                run([BASE_DIR / "data/auth.log"],
                    BASE_DIR / "data/blacklist.txt", out)
            self.assertEqual(summary.read_text(), "ancien résultat")

    def test_publication_failure_restores_previous_results(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            source = out / "empty.log"
            source.touch()
            alerts = out / "alerts.jsonl"
            alerts.write_bytes(b"anciennes alertes")
            audit = out / "audit.json"
            audit.write_bytes(b"ancien audit")
            replace = Path.replace

            def fail_on_new_alerts(path: Path, target: Path) -> Path:
                if target == alerts and path.parent.name.startswith("tmp"):
                    raise PermissionError("publication interrompue")
                return replace(path, target)

            with patch.object(Path, "replace", fail_on_new_alerts):
                with self.assertRaisesRegex(PermissionError, "interrompue"):
                    run([source], BASE_DIR / "data/blacklist.txt", out)

            self.assertEqual(alerts.read_bytes(), b"anciennes alertes")
            self.assertEqual(audit.read_bytes(), b"ancien audit")
            self.assertCountEqual(out.iterdir(), [source, alerts, audit])

    def test_publication_does_not_touch_another_run(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            source = out / "empty.log"
            source.touch()
            lock = out / ".securelog-publish"
            lock.mkdir()
            backup = lock / "summary.json"
            backup.write_bytes(b"autre analyse en cours")
            with self.assertRaisesRegex(FileExistsError, "verrouillée"):
                run([source], BASE_DIR / "data/blacklist.txt", out)
            self.assertCountEqual(out.iterdir(), [source, lock])
            self.assertEqual(backup.read_bytes(), b"autre analyse en cours")

    def test_cli_errors(self):
        for arguments, expected in [
            (["--threshold", "0"], 2), (["fichier_absent.log"], 1),
            (["--strict"], 1), (["-", "-"], 1),
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
