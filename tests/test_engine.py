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


