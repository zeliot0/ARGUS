"""Runs the selected checks and assembles the report."""
from __future__ import annotations

import platform as _platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .checks_browser import check_browsers
from .checks_connections import check_connections
from .checks_extensions import check_extensions
from .checks_files import MAX_FILES, check_files
from .checks_history import check_history
from .checks_network import check_dns_cache, check_hosts
from .checks_persistence import check_persistence
from .checks_ports import check_ports
from .checks_processes import check_processes
from .checks_wmi import check_wmi
from .evidence import CheckResult, Finding
from .ioc import IndicatorSet

SCHEMA_VERSION = 1
CHECK_NAMES = (
    "browser", "files", "persistence", "hosts", "dns-cache", "connections",
    "wmi", "extensions", "history", "processes", "ports",
)

# progress(event, check_name, result): event is "start" or "done"; result is None on "start".
Progress = Callable[[str, str, Optional[CheckResult]], None]


def _checks(quick: bool, max_files: int, tick: Optional[Callable[[int], None]] = None, deep: bool = False) -> Dict[str, Callable[[IndicatorSet], CheckResult]]:
    return {
        "browser": lambda ind: check_browsers(ind),
        "files": lambda ind: check_files(ind, quick=quick, max_files=max_files, tick=tick, skip_caches=not deep),
        "persistence": lambda ind: check_persistence(ind),
        "hosts": lambda ind: check_hosts(ind),
        "dns-cache": lambda ind: check_dns_cache(ind),
        "connections": lambda ind: check_connections(ind),
        "wmi": lambda ind: check_wmi(ind),
        "extensions": lambda ind: check_extensions(ind),
        "history": lambda ind: check_history(ind),
        "processes": lambda ind: check_processes(ind, quick=quick),
        "ports": lambda ind: check_ports(ind),
    }


@dataclass
class ScanReport:
    started: str
    platform: str
    indicator_count: int
    results: List[CheckResult] = field(default_factory=list)
    not_run: List[str] = field(default_factory=list)

    @property
    def findings(self) -> List[Finding]:
        return [f for r in self.results for f in r.findings]

    @property
    def actionable(self) -> List[Finding]:
        return [f for f in self.findings if f.severity != "info"]

    @property
    def gaps(self) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        for r in self.results:
            if r.status != "ran":
                out.append((r.name, r.note or r.status))
            out.extend((r.name, g) for g in r.gaps)
        out.extend((name, "not selected for this scan") for name in self.not_run)
        return out

    @property
    def complete(self) -> bool:
        return not self.gaps

    def exit_code(self) -> int:
        return 2 if self.actionable else 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "handling": "Contains unredacted indicator values. Treat this file as sensitive.",
            "started": self.started,
            "platform": self.platform,
            "indicator_count": self.indicator_count,
            "verdict": verdict(self),
            "complete": self.complete,
            "exit_code": self.exit_code(),
            "not_run": list(self.not_run),
            "checks": [r.to_dict() for r in self.results],
        }


def verdict(report: ScanReport) -> str:
    if report.actionable:
        return (
            "INDICATOR MATCHES FOUND. Do not delete the evidence. Read each finding and the check "
            "behind it; one weak match is not proof of infection."
        )
    return (
        "No known indicator was found in the checks that ran. This is NOT a clean bill of health: "
        "see the gaps listed below."
    )


def run_scan(
    indicators: IndicatorSet,
    quick: bool = False,
    max_files: int = MAX_FILES,
    only: Optional[Sequence[str]] = None,
    progress: Optional[Progress] = None,
    tick: Optional[Callable[[int], None]] = None,
    deep: bool = False,
) -> ScanReport:
    wanted = list(CHECK_NAMES) if only is None else list(only)
    unknown = [n for n in wanted if n not in CHECK_NAMES]
    if unknown:
        raise ValueError(f"unknown check(s): {', '.join(unknown)}")

    report = ScanReport(
        started=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        platform=f"{_platform.system()} {_platform.release()}",
        indicator_count=len(indicators),
        not_run=[n for n in CHECK_NAMES if n not in wanted],
    )
    available = _checks(quick, max_files, tick, deep)
    for name in CHECK_NAMES:
        if name not in wanted:
            continue
        if progress:
            progress("start", name, None)
        try:
            result = available[name](indicators)
        except Exception as exc:  # one broken check must not hide the others
            result = CheckResult(name, status="error", note=f"{exc.__class__.__name__}: {exc}")
        report.results.append(result)
        if progress:
            progress("done", name, result)
    return report
