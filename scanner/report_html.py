"""Self-contained HTML report. No scripts, no external resources, every value escaped.

File names and paths come from the scanned machine and may contain markup, so nothing
is inserted into the page without html.escape.
"""
from __future__ import annotations

from html import escape
from typing import List

from .evidence import SEVERITY_ORDER
from .report import EXPERT_HELP, defang
from .runner import ScanReport, verdict

CSS = """
:root{--bg:#ffffff;--fg:#1b1f24;--muted:#5b6570;--card:#f4f6f8;--line:#dde2e7;--high:#c62828;--medium:#b26a00;--low:#0b6b8a;--info:#6b7480;--ok:#1b7f3b}
@media (prefers-color-scheme:dark){:root{--bg:#12161b;--fg:#e6e9ed;--muted:#9aa5b1;--card:#1b2128;--line:#2b333c;--high:#ff6b6b;--medium:#f0b24a;--low:#5cc2e0;--info:#98a2ae;--ok:#58d17a}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 48px}
h1{margin:0;font-size:28px;letter-spacing:.14em}
h2{margin:32px 0 10px;font-size:17px}
.sub{color:var(--muted);margin:4px 0 20px}
.verdict{border:1px solid var(--line);border-left:6px solid var(--ok);background:var(--card);padding:14px 16px;border-radius:6px}
.verdict.bad{border-left-color:var(--high)}
.verdict b{display:block;margin-bottom:4px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 12px}
.card .n{font-size:26px;font-weight:600}
.card .l{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.06em}
.high .n{color:var(--high)}.medium .n{color:var(--medium)}.low .n{color:var(--low)}.info .n{color:var(--info)}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
td.num{text-align:right;font-variant-numeric:tabular-nums}
code{font:13px ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all}
.tag{font-weight:700;font-size:12px;letter-spacing:.05em}
.tag.high{color:var(--high)}.tag.medium{color:var(--medium)}.tag.low{color:var(--low)}.tag.info{color:var(--info)}
ul{padding-left:20px}li{margin:3px 0}
footer{margin-top:36px;color:var(--muted);font-size:13px}
@media (max-width:640px){.cards{grid-template-columns:repeat(2,1fr)}}
@media print{body{background:#fff;color:#000}}
"""


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def render_html(report: ScanReport) -> str:
    actionable = bool(report.actionable)
    counts = {sev: sum(1 for f in report.findings if f.severity == sev) for sev in SEVERITY_ORDER}
    out: List[str] = []
    add = out.append

    add("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    add("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">")
    add("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>ARGUS report</title>")
    add(f"<style>{CSS}</style></head><body><main>")
    add("<h1>ARGUS</h1>")
    add(f"<p class=\"sub\">Indicator check &middot; started {_e(report.started)} &middot; {_e(report.platform)} &middot; {_e(report.indicator_count)} indicators</p>")

    headline = "Indicator matches found" if actionable else "No known indicator found"
    add(f"<section class=\"verdict{' bad' if actionable else ''}\"><b>{_e(headline)}</b>{_e(verdict(report))}</section>")

    add("<div class=\"cards\">")
    for sev in SEVERITY_ORDER:
        add(f"<div class=\"card {sev}\"><div class=\"n\">{counts[sev]}</div><div class=\"l\">{sev}</div></div>")
    add("</div>")

    add("<h2>Checks</h2><table><tr><th>Check</th><th>Status</th><th class=\"num\">Examined</th><th class=\"num\">Findings</th></tr>")
    for r in report.results:
        add(f"<tr><td>{_e(r.name)}</td><td>{_e(r.status)}</td><td class=\"num\">{r.examined:,}</td><td class=\"num\">{len(r.findings)}</td></tr>")
    for name in report.not_run:
        add(f"<tr><td>{_e(name)}</td><td>not run</td><td class=\"num\">-</td><td class=\"num\">-</td></tr>")
    add("</table>")

    findings = sorted(report.findings, key=lambda f: SEVERITY_ORDER.index(f.severity))
    add(f"<h2>Findings ({len(findings)})</h2>")
    if not findings:
        add("<p>None.</p>")
    else:
        add("<table><tr><th>Severity</th><th>What</th><th>Indicator</th><th>Where</th></tr>")
        for f in findings:
            ind = f.indicator
            add(
                f"<tr><td><span class=\"tag {_e(f.severity)}\">{_e(f.severity.upper())}</span></td>"
                f"<td>{_e(f.grade)}<br><span class=\"sub\">{_e(f.detail)}</span></td>"
                f"<td><code>{_e(defang(ind.value, ind.kind))}</code><br>"
                f"<span class=\"sub\">{_e(ind.kind)} &middot; {_e(ind.tier)} &middot; {_e(ind.campaign or 'n/a')}"
                f"<br>source: {_e(ind.source or 'n/a')}</span></td>"
                f"<td><code>{_e(f.location)}</code></td></tr>"
            )
        add("</table>")

    gaps = report.gaps
    add(f"<h2>Could not check ({len(gaps)})</h2>")
    if not gaps:
        add("<p>Nothing was skipped.</p>")
    else:
        add("<ul>" + "".join(f"<li><b>{_e(name)}</b>: {_e(text)}</li>" for name, text in gaps) + "</ul>")

    add(f"<footer>{_e(EXPERT_HELP)}<br>This report lists file paths. Share it carefully.</footer>")
    add("</main></body></html>")
    return "".join(out)
