"""Pipeline paresseux : filtrage, parsing, puis normalisation."""

import logging
from collections.abc import Iterable, Iterator
from typing import Any

from .ingestion import SourceLine
from .parser import Log, parse_log


