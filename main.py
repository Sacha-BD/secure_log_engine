"""Démonstration CLI du pipeline SecureLog Engine."""

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


