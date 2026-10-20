"""A snapshot of the autostart/listener surface, taken independent of any indicator feed.

Catches something new even if no feed knows about it yet. A later scan is compared against
the snapshot, and anything not seen at baseline time is reported as new. A heuristic signal,
not a claim that it's malicious: a software update shows up here too.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .runner import ScanReport

CONFIG_NAME = "baseline.json"
INVENTORY_CHECKS = ("persistence", "wmi", "ports")
Item = Tuple[str, str, str]  # check, location, detail


def collect(report: ScanReport) -> List[Item]:
    items: List[Item] = []
    for r in report.results:
        if r.name in INVENTORY_CHECKS:
            items.extend((r.name, location, detail) for location, detail in r.inventory)
    return items


def exists(directory: Path) -> bool:
    return (Path(directory) / CONFIG_NAME).is_file()


def set_baseline(directory: Path, report: ScanReport) -> Optional[str]:
    directory = Path(directory)
    items = collect(report)
    checks_covered = sorted({r.name for r in report.results if r.name in INVENTORY_CHECKS and r.status == "ran"})
    payload = {
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "checks_covered": checks_covered,
        "items": [list(item) for item in items],
    }
    try:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / CONFIG_NAME).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as exc:
        return f"could not save the baseline: {exc}"
    return None


def load(directory: Path) -> Optional[Dict[str, Any]]:
    path = Path(directory) / CONFIG_NAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or "items" not in data:
        return None
    return data


@dataclass
class BaselineDiff:
    created: str
    new: List[Item] = field(default_factory=list)
    not_covered: List[str] = field(default_factory=list)  # baselined checks that didn't run this time


def compare(baseline: Dict[str, Any], report: ScanReport) -> BaselineDiff:
    ran_now = {r.name for r in report.results if r.status == "ran"}
    diff = BaselineDiff(created=str(baseline.get("created", "unknown")))
    diff.not_covered = [c for c in baseline.get("checks_covered", []) if c not in ran_now]
    known: Set[Item] = set()
    for row in baseline.get("items", []):
        try:
            known.add((row[0], row[1], row[2]))
        except (IndexError, TypeError):
            continue
    for item in collect(report):
        check = item[0]
        if check in ran_now and item not in known:
            diff.new.append(item)
    return diff
