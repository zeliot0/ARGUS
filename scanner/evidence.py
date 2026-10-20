"""Findings and check results.

A grade says what the artifact itself proves. Severity follows from the grade, and
drops one level when the indicator is only a "lead" tier.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from .ioc import Indicator

SEVERITY_ORDER = ("high", "medium", "low", "info")

GRADES: Dict[str, tuple] = {
    "file-match": ("high", "A file on disk has the exact SHA-256 of a published sample."),
    "connection": ("high", "A network connection to an indicator IP is open right now."),
    "autostart": ("high", "A program registered to start automatically matches an indicator."),
    "visit": ("medium", "Browser history records a visit to an indicator domain."),
    "hosts-config": ("medium", "The hosts file maps an indicator domain to a non-local address."),
    "dns-cache": ("medium", "The DNS resolver cache holds an indicator domain; a lookup may have failed."),
    "name-lead": ("low", "A file has a name used by the campaign. The name alone is weak evidence."),
    "cookie-lead": ("low", "A cookie host matches an indicator domain. Cookie metadata alone does not prove contact."),
    "hosts-sink": ("info", "The hosts file blocks an indicator domain. This is protective configuration."),
    "extension": ("high", "An installed browser extension's ID matches a published malicious extension."),
    "wmi-consumer": ("high", "A WMI event subscription is configured to run a program matching an indicator."),
    "com-hijack": ("high", "A per-user COM class override points at a program matching an indicator."),
    "shell-history": ("low", "Command history mentions an indicator domain, IP or file name. This is weak evidence; the command may not have run or succeeded."),
    "process-match": ("high", "A running process's on-disk executable has the exact SHA-256 of a published sample."),
    "process-name-lead": ("low", "A running process has a name used by a campaign. The name alone is weak evidence."),
    "listener-lead": ("low", "A program listening for incoming connections has a name used by a campaign. The name alone is weak evidence."),
}


def severity_for(grade: str, tier: str) -> str:
    severity = GRADES[grade][0]
    if tier == "lead":
        idx = SEVERITY_ORDER.index(severity)
        severity = SEVERITY_ORDER[min(idx + 1, len(SEVERITY_ORDER) - 1)]
    return severity


@dataclass
class Finding:
    check: str
    grade: str
    severity: str
    indicator: Indicator
    location: str
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check": self.check,
            "grade": self.grade,
            "severity": self.severity,
            "indicator": {
                "kind": self.indicator.kind,
                "value": self.indicator.value,
                "tier": self.indicator.tier,
                "confidence": self.indicator.confidence,
                "source": self.indicator.source,
                "campaign": self.indicator.campaign,
            },
            "location": self.location,
            "detail": self.detail,
        }


def make_finding(check: str, grade: str, indicator: Indicator, location: str, detail: str) -> Finding:
    if grade not in GRADES:
        raise ValueError(f"unknown grade {grade!r}")
    return Finding(
        check=check,
        grade=grade,
        severity=severity_for(grade, indicator.tier),
        indicator=indicator,
        location=location,
        detail=detail,
    )


@dataclass
class CheckResult:
    name: str
    status: str = "ran"  # ran | skipped | error
    note: str = ""
    examined: int = 0
    gaps: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    # (location, detail) pairs for baseline.py; only persistence/ports/wmi fill this in.
    inventory: List["Tuple[str, str]"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "note": self.note,
            "examined": self.examined,
            "gaps": list(self.gaps),
            "findings": [f.to_dict() for f in self.findings],
            "inventory": [list(item) for item in self.inventory],
        }
