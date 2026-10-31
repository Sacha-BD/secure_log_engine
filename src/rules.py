"""Règles indépendantes passées comme objets au moteur de sécurité."""

from collections import deque
from collections.abc import Callable, Iterator
from typing import Any

from .parser import Log

Alert = dict[str, Any]
Rule = Callable[..., Alert | None]
History = dict[tuple[str, str], deque[bool]]


