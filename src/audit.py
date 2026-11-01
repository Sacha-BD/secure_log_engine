"""Audit des portées sans recopier les données ni les secrets éventuels."""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

AUDIT_VERSION = "1.0"


