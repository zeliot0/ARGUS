"""Scan history and comparison with the previous scan.

Only checks that ran in both scans are compared, so a skipped check's old findings are
never reported as resolved.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .evidence import Finding
from .runner import ScanReport

KEEP = 50
Key = Tuple[str, str, str, str, str]


def finding_key(check: str, grade: str, kind: str, value: str, location: str) -> Key:
    return (check, grade, kind, value, location)


def _key_of(f: Finding) -> Key:
    return finding_key(f.check, f.grade, f.indicator.kind, f.indicator.value, f.location)


def summarize(report: ScanReport) -> Dict[str, Any]:
    return {
        "started": report.started,
        "platform": report.platform,
        "indicator_count": report.indicator_count,
        "checks_run": [r.name for r in report.results if r.status == "ran"],
        "gap_count": len(report.gaps),
        "findings": [
            {
                "check": f.check, "grade": f.grade, "severity": f.severity,
                "kind": f.indicator.kind, "value": f.indicator.value, "location": f.location,
            }
            for f in report.findings
        ],
    }


def save(history_dir: Path, report: ScanReport) -> Path:
    history_dir = Path(history_dir)
    history_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = history_dir / f"scan-{stamp}.json"
    path.write_text(json.dumps(summarize(report), indent=2), encoding="utf-8")
    for old in sorted(history_dir.glob("scan-*.json"))[:-KEEP]:
        try:
            old.unlink()
        except OSError:
            pass
    return path


def load_latest(history_dir: Path) -> Optional[Dict[str, Any]]:
    """The newest readable summary, or None. Corrupt files are ignored."""
    history_dir = Path(history_dir)
    if not history_dir.is_dir():
        return None
    for path in sorted(history_dir.glob("scan-*.json"), reverse=True):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("findings"), list):
            return data
    return None


def load_recent(history_dir: Path, limit: int = 8) -> List[Dict[str, Any]]:
    """Up to `limit` readable summaries, oldest first. Corrupt files are skipped, not counted."""
    history_dir = Path(history_dir)
    if not history_dir.is_dir():
        return []
    out: List[Dict[str, Any]] = []
    for path in sorted(history_dir.glob("scan-*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("findings"), list):
            out.append(data)
    return out[-limit:]


def actionable_count(summary: Dict[str, Any]) -> int:
    return sum(1 for f in summary.get("findings", []) if f.get("severity") != "info")


@dataclass
class Diff:
    previous_started: str
    new: List[Finding] = field(default_factory=list)
    resolved: List[Dict[str, Any]] = field(default_factory=list)
    unchanged: int = 0
    not_compared: List[str] = field(default_factory=list)  # checks that ran then but not now


def compare(previous: Dict[str, Any], report: ScanReport) -> Diff:
    ran_now = {r.name for r in report.results if r.status == "ran"}
    diff = Diff(previous_started=str(previous.get("started", "unknown")))
    diff.not_compared = [c for c in previous.get("checks_run", []) if c not in ran_now]
    old: Dict[Key, Dict[str, Any]] = {}
    for item in previous.get("findings", []):
        try:
            old[finding_key(item["check"], item["grade"], item["kind"], item["value"], item["location"])] = item
        except (KeyError, TypeError):
            continue
    current = {_key_of(f): f for f in report.findings}
    for key, finding in current.items():
        if key in old:
            diff.unchanged += 1
        else:
            diff.new.append(finding)
    for key, item in old.items():
        if key not in current and item["check"] in ran_now:
            diff.resolved.append(item)
    return diff
