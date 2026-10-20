"""Findings marked reviewed, so they stop showing up as actionable.

Keyed on (check, grade, indicator kind, value, location), the same fields history.py
tracks a finding by. A reviewed finding is hidden from the display, never deleted from
the saved report.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .evidence import Finding
from .runner import ScanReport

CONFIG_NAME = "allowlist.json"
Key = Tuple[str, str, str, str, str]


def _key_of(f: Finding) -> Key:
    return (f.check, f.grade, f.indicator.kind, f.indicator.value, f.location)


@dataclass
class Entry:
    key: Key
    note: str = ""


def load(path: Path) -> Dict[Key, Entry]:
    path = Path(path) / CONFIG_NAME
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    out: Dict[Key, Entry] = {}
    for item in data.get("entries", []) if isinstance(data, dict) else []:
        try:
            key = (item["check"], item["grade"], item["kind"], item["value"], item["location"])
        except (KeyError, TypeError):
            continue
        out[key] = Entry(key, str(item.get("note", "")))
    return out


def save(directory: Path, entries: Dict[Key, Entry]) -> Optional[str]:
    directory = Path(directory)
    payload = {
        "entries": [
            {"check": k[0], "grade": k[1], "kind": k[2], "value": k[3], "location": k[4], "note": e.note}
            for k, e in entries.items()
        ]
    }
    try:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / CONFIG_NAME).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as exc:
        return f"could not save the allowlist: {exc}"
    return None


def add(directory: Path, finding: Finding, note: str = "") -> Dict[Key, Entry]:
    entries = load(directory)
    entries[_key_of(finding)] = Entry(_key_of(finding), note)
    save(directory, entries)
    return entries


def remove(directory: Path, key: Key) -> Dict[Key, Entry]:
    entries = load(directory)
    entries.pop(key, None)
    save(directory, entries)
    return entries


def split(report: ScanReport, entries: Dict[Key, Entry]) -> Tuple[List[Finding], List[Finding]]:
    """(visible findings, allowed findings) — allowed ones matched an allowlist entry."""
    visible: List[Finding] = []
    allowed: List[Finding] = []
    for f in report.findings:
        (allowed if _key_of(f) in entries else visible).append(f)
    return visible, allowed
