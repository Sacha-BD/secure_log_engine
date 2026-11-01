"""Audit des portées sans recopier les données ni les secrets éventuels."""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

AUDIT_VERSION = "1.0"


def describe_scope(scope: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Exporter nom, type et taille des conteneurs, sans leur contenu."""
    result = {}
    for name, value in sorted(scope.items()):
        if name.startswith("__"):
            continue
        metadata: dict[str, Any] = {"type": type(value).__name__}
        if isinstance(value, (dict, list, tuple, set, frozenset, str)):
            metadata["size"] = len(value)
        result[name] = metadata
    return result


def export_audit(
    path: Path,
    global_scope: Mapping[str, Any],
    local_scope: Mapping[str, Any],
) -> None:
    """Recevoir les portées réelles du pipeline et inspecter ce module."""
    report = {
        "version": AUDIT_VERSION,
        "pipeline_globals": describe_scope(global_scope),
        "pipeline_locals": describe_scope(local_scope),
        "audit_globals": describe_scope(globals()),
        "audit_locals": describe_scope(locals()),
    }
    path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
