"""Human-readable text report. Indicator values are defanged so a forwarded report
cannot make a mail client or browser contact them."""
from __future__ import annotations

from typing import List

from .evidence import SEVERITY_ORDER, Finding
from .runner import ScanReport, verdict

EXPERT_HELP = (
    "If you have a credible reason to believe you are being targeted, get expert help before "
    "acting: Access Now Digital Security Helpline (accessnow.org/help) or Amnesty International "
    "Security Lab (securitylab.amnesty.org)."
)


def defang(value: str, kind: str) -> str:
    if kind in ("domain", "ip"):
        value = value.replace(".", "[.]")
        if kind == "ip" and ":" in value:
            value = value.replace(":", "[:]")
    return value


def _label(f: Finding) -> str:
    ind = f.indicator
    shown = defang(ind.value, ind.kind)
    return f"{ind.kind} {shown} [{ind.campaign or 'n/a'}] ({ind.tier}, confidence {ind.confidence or 'n/a'}, source: {ind.source or 'n/a'})"


def render_text(report: ScanReport) -> str:
    out: List[str] = []
    add = out.append
    add("ARGUS: indicator check")
    add(f"Started:            {report.started}")
    add(f"Platform:           {report.platform}")
    add(f"Indicators loaded:  {report.indicator_count}")
    add("")
    add("VERDICT")
    add("  " + verdict(report))
    add("")

    findings = sorted(report.findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
    add(f"FINDINGS ({len(findings)})")
    if not findings:
        add("  none")
    for f in findings:
        add(f"  [{f.severity.upper()}] {f.grade}: {_label(f)}")
        add(f"      where:  {f.location}")
        add(f"      detail: {f.detail}")
    add("")

    gaps = report.gaps
    add(f"COULD NOT CHECK ({len(gaps)})")
    if not gaps:
        add("  nothing was skipped")
    for name, text in gaps:
        add(f"  - [{name}] {text}")
    add("")

    add("CHECKS")
    for r in report.results:
        add(f"  {r.name:<12} {r.status:<8} examined {r.examined}" + (f"  ({r.note})" if r.note else ""))
    add("")
    add(EXPERT_HELP)
    return "\n".join(out)


# Public alias used by the interactive console.
describe_indicator = _label
