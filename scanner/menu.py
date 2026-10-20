"""ARGUS interactive console: numbered menus, colour, live progress. No dependencies."""
from __future__ import annotations

import json
import random
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence, Set, Tuple

from . import __version__, netguard
from .checks_files import MAX_FILES
from .evidence import SEVERITY_ORDER, CheckResult
from .feeds import DEFAULT_FEEDS_DIR, Feed, build_set, discover_feeds, load_disabled, save_disabled
from .ioc import IOCError, IndicatorSet, load_indicators
from .report import EXPERT_HELP, defang, describe_indicator, render_text
from . import allowlist, baseline, history
from .report_html import render_html
from .runner import CHECK_NAMES, ScanReport, run_scan, verdict
from .ui import MANIFESTO_LINES, Console, Spinner, safe_console

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORTS = PROJECT_ROOT / "reports"

CHECK_INFO = {
    "browser": "history and cookie host names (Chrome, Edge, Brave, Firefox)",
    "files": "file names and SHA-256 in Downloads, Desktop, Documents, Temp, AppData",
    "persistence": "auto-start entries (registry Run keys, LaunchAgents, autostart/systemd)",
    "hosts": "hosts file entries",
    "dns-cache": "Windows DNS resolver cache (names and IP answers)",
    "connections": "network connections open right now, against IP indicators",
    "wmi": "WMI event subscriptions and per-user COM class overrides (Windows)",
    "extensions": "installed browser extension IDs and names",
    "history": "shell / PowerShell command history for indicator mentions",
    "processes": "running processes, by on-disk SHA-256 and by name",
    "ports": "TCP ports listening for incoming connections, by owning process name",
}

CHECK_PLATFORMS = {
    "browser": "Windows, macOS, Linux",
    "files": "Windows, macOS, Linux",
    "persistence": "Windows, macOS, Linux (different sources per platform)",
    "hosts": "Windows, macOS, Linux",
    "dns-cache": "Windows only",
    "connections": "Windows, macOS, Linux",
    "wmi": "Windows only",
    "extensions": "Windows, macOS, Linux",
    "history": "Windows, macOS, Linux",
    "processes": "Windows, macOS, Linux",
    "ports": "Windows, macOS, Linux",
}

MAIN_ITEMS = [
    ("1", "Full scan", "all checks, hashes file contents"),
    ("2", "Quick scan", "all checks, skips file hashing"),
    ("3", "Custom scan", "pick which checks to run"),
    ("4", "Indicator feeds", "switch campaigns on or off, load a CSV"),
    ("5", "Reports", "view, save, open in browser"),
    ("6", "Settings", "limits and colour"),
    ("7", "About", "what ARGUS does and does not do"),
    ("8", "Checks", "what each check looks at, and last scan's numbers"),
    ("0", "Exit", ""),
]

GAUGE_COLOURS = ("c46", "c154", "c226", "c208", "c196")


def threat_level(findings: Sequence) -> Tuple[str, int, str]:
    """(label, filled segments out of 5, colour). Takes a list of findings, or a ScanReport
    for the unfiltered level. Never says 'safe': no match is not proof."""
    if isinstance(findings, ScanReport):
        findings = findings.findings
    severities = {f.severity for f in findings}
    if "high" in severities:
        return "CRITICAL", 5, "red"
    if "medium" in severities:
        return "ELEVATED", 3, "red"
    if "low" in severities:
        return "GUARDED", 2, "yellow"
    return "NO KNOWN INDICATORS", 0, "green"


SEVERITY_STYLE = {
    "high": ("red", "bold"),
    "medium": ("yellow", "bold"),
    "low": ("cyan",),
    "info": ("grey",),
}
SEVERITY_BADGE = {"high": "c196", "medium": "c208", "low": "c33", "info": "c240"}
STATUS_STYLE = {"ran": ("green",), "skipped": ("yellow",), "error": ("red", "bold")}


def parse_selection(text: str, names: Sequence[str]) -> List[str]:
    """'1 3', '1,3', 'browser hosts' or 'all' -> check names in canonical order."""
    text = text.strip().lower()
    if text in ("a", "all"):
        return list(names)
    chosen: List[str] = []
    for token in text.replace(",", " ").split():
        if token.isdigit():
            index = int(token)
            if not 1 <= index <= len(names):
                raise ValueError(f"there is no check number {token}")
            name = names[index - 1]
        elif token in names:
            name = token
        else:
            raise ValueError(f"unknown check {token!r}")
        if name not in chosen:
            chosen.append(name)
    if not chosen:
        raise ValueError("nothing was selected")
    return [n for n in names if n in chosen]


def parse_feed_tokens(text: str, names: Sequence[str]) -> List[str]:
    """Feed numbers (1-based) or exact names -> names, in the order given."""
    out: List[str] = []
    for token in text.replace(",", " ").split():
        if token.isdigit():
            index = int(token)
            if not 1 <= index <= len(names):
                raise ValueError(f"there is no feed number {token}")
            name = names[index - 1]
        elif token in names:
            name = token
        else:
            raise ValueError(f"unknown feed {token!r}")
        if name not in out:
            out.append(name)
    if not out:
        raise ValueError("nothing was selected")
    return out


def is_placeholder(indicators: IndicatorSet) -> bool:
    items = indicators.all()
    return bool(items) and all(i.source.lower().startswith("placeholder") for i in items)


class App:
    def __init__(
        self,
        console: Console,
        feed_path: Optional[Path] = None,
        reports_dir: Path = DEFAULT_REPORTS,
        max_files: int = MAX_FILES,
        feeds_dir: Path = DEFAULT_FEEDS_DIR,
    ):
        self.c = console
        self.source_file: Optional[Path] = Path(feed_path) if feed_path else None  # a CSV used instead of the feeds
        self.feeds_dir = Path(feeds_dir)
        self.feeds: List[Feed] = []
        self.disabled: Set[str] = set()
        self.reports_dir = Path(reports_dir)
        self.max_files = max_files
        self.hash_files = True
        self.deep = False
        self.diff: Optional[history.Diff] = None
        self.allowlist: dict = {}
        self.selected = list(CHECK_NAMES)
        self.indicators: Optional[IndicatorSet] = None
        self.feed_error: Optional[str] = None
        self.report: Optional[ScanReport] = None
        self.last_html: Optional[Path] = None

    # ---- feeds ------------------------------------------------------------
    def load_feed(self, path) -> Optional[str]:
        """Use one CSV instead of the feeds folder. Returns an error message, or None on success."""
        try:
            loaded = load_indicators(path)
        except IOCError as exc:
            return str(exc)
        self.indicators = IndicatorSet(loaded)
        self.source_file = Path(path)
        self.feed_error = None
        return None

    def reload_feeds(self) -> None:
        """Read the feeds folder and apply the on/off settings."""
        self.source_file = None
        self.disabled = load_disabled(self.feeds_dir)
        self.feeds = discover_feeds(self.feeds_dir, self.disabled)
        self._rebuild()

    def _rebuild(self) -> None:
        built = build_set(self.feeds)
        self.indicators = built
        if built is not None:
            self.feed_error = None
        elif self.feeds:
            self.feed_error = "no feeds are switched on"
        else:
            self.feed_error = f"no feed files found in {self.feeds_dir}"

    def print_feed_table(self) -> None:
        c = self.c
        for i, f in enumerate(self.feeds, 1):
            mark = "[x]" if f.enabled else "[ ]"
            kinds = ", ".join(f"{n:,} {k}" for k, n in sorted(f.kinds.items()))
            c.say(f"  {i:>2}) {mark} {f.name:<30}{f.count:>6,}  {c.paint(kinds, 'grey')}")
            if f.error:
                c.say(c.paint(f"        unreadable: {f.error}", "red"))

    # ---- generic menu -----------------------------------------------------
    def menu(self, title: str, items: Sequence[Tuple[str, str, str]], crumb: str = "", accent: str = "c160") -> str:
        c = self.c
        c.say()
        width = max((len(label) for _, label, hint in items if hint), default=0) + 2
        if c.unicode:
            rows = []
            for key, label, hint in items:
                badge = c.paint(f"[{key}]", "bold", "yellow")
                rows.append(f"{badge} {c.paint(label.ljust(width), 'bold')}{c.paint(hint, 'grey')}")
            c.panel(title, rows, accent)
        else:
            c.say(c.paint(f"[ {title} ]", "bold", "cyan"))
            for key, label, hint in items:
                c.say(f"  {c.paint(key.rjust(2), 'bold', 'yellow')})  {label.ljust(width)}{c.paint(hint, 'grey')}")
        keys = {k for k, _, _ in items}
        prompt = "argus" + (f"/{crumb}" if crumb else "") + ">"
        while True:
            choice = c.ask(prompt).lower()
            if choice in keys:
                return choice
            c.say(c.paint("  Not a valid choice. Enter one of: " + ", ".join(sorted(keys)), "red"))

    def pause(self) -> None:
        self.c.ask("Press Enter to continue")

    # ---- screens ----------------------------------------------------------
    def status_accent(self) -> str:
        """The colour a report's state earns: red for a match, green for clean, the house
        colour otherwise. Shared by the header panel and the main menu border."""
        if self.report is None:
            return "c160"
        return "c196" if self.report.actionable else "c46"

    def show_header(self) -> None:
        c = self.c
        c.clear()
        c.banner()
        sep = "·" if c.unicode else "|"
        c.say(c.paint(f" v{__version__}  read-only, offline indicator scanner  {sep}  Windows, macOS, Linux", "grey"))
        c.say()

        dot = c.g["dot"]
        rows = [
            c.paint(f"{dot} ARGUS ONLINE", "red", "bold") + "   "
            + c.paint(f"{dot} NETWORK LOCKED", "green", "bold") + "   "
            + c.paint(f"{dot} READ-ONLY", "green", "bold"),
            "",
        ]
        if self.indicators is not None:
            if self.source_file is not None:
                rows.append(f"Feed       {self.source_file.name}  ({len(self.indicators):,} indicators)")
            else:
                on = sum(1 for f in self.feeds if f.enabled and not f.error)
                rows.append(f"Feeds      {on} of {len(self.feeds)} switched on  ({len(self.indicators):,} indicators)")
        else:
            rows.append(c.paint(f"Feed       not loaded: {self.feed_error}", "red"))

        if self.report is not None:
            bad = len(self.report.actionable)
            mark = c.paint(dot, "red" if bad else "green", "bold")
            rows.append(f"Last scan  {mark} {self.report.started}  {bad} actionable finding(s), {len(self.report.gaps)} gap(s)")
        else:
            rows.append("Last scan  none yet")

        recent = history.load_recent(self.history_dir, 10)
        if len(recent) >= 2:
            counts = [history.actionable_count(r) for r in recent]
            rows.append(f"Trend      {c.sparkline(counts)}  actionable findings, last {len(recent)} scan(s)")

        accent = self.status_accent()
        c.panel("STATUS", rows, accent)

        if self.indicators is not None and is_placeholder(self.indicators):
            c.wrapped(
                "PLACEHOLDER DATA: these are fake test indicators. A scan proves the tool runs, "
                "not that your machine is clean. Load a sourced feed (Indicator feeds menu).",
                "  ! ", "    ", "yellow", "bold",
            )

    def show_report(self, report: ScanReport) -> None:
        c = self.c
        visible, allowed = allowlist.split(report, self.allowlist)
        actionable = any(f.severity != "info" for f in visible)
        c.say()
        headline = "RESULT: INDICATOR MATCHES FOUND" if actionable else "RESULT: NO KNOWN INDICATOR FOUND"
        label, filled, colour = threat_level(visible)
        g = c.g
        gauge = "".join(
            c.paint(g["seg"], GAUGE_COLOURS[i], "bold") if i < filled else c.paint(g["seg_off"], "grey")
            for i in range(5)
        )
        c.say(f"  THREAT LEVEL  {gauge}  {c.paint(label, colour, 'bold')}")
        if not report.complete and not actionable:
            c.say(c.paint("                (coverage incomplete: see the gaps below)", "grey"))
        if allowed:
            c.say(c.paint(f"                ({len(allowed)} finding(s) marked reviewed and excluded above)", "grey"))
        c.say()
        c.box([headline, "", verdict(report)], "red" if actionable else "green", "bold", double=actionable)

        counts = {sev: sum(1 for f in visible if f.severity == sev) for sev in SEVERITY_ORDER}
        peak = max(max(counts.values()), 1)
        c.say()
        c.header("SEVERITY")
        for sev in SEVERITY_ORDER:
            c.say(f"  {sev:<8}{c.bar(counts[sev], peak, 20, *SEVERITY_STYLE[sev])} {counts[sev]}")

        c.say()
        c.header("CHECKS")
        c.say(c.paint(f"  {'check':<13}{'status':<9}{'examined':>10}{'findings':>10}", "grey"))
        for r in report.results:
            status = c.paint(f"{r.status:<9}", *STATUS_STYLE.get(r.status, ()))
            icon = ""
            if c.unicode:
                icon = c.paint(c.g["bad"] if r.findings else c.g["ok"] if r.status == "ran" else c.g["warn"],
                               "red" if r.findings else "green" if r.status == "ran" else "yellow", "bold") + " "
            c.say(f"  {icon}{r.name:<13}{status}{r.examined:>10,}{len(r.findings):>10}")
        for name in report.not_run:
            c.say(c.paint(f"  {name:<13}{'not run':<9}", "grey"))

        findings = sorted(visible, key=lambda f: SEVERITY_ORDER.index(f.severity))
        c.say()
        header = f"FINDINGS ({len(findings)})"
        if allowed:
            header += f"  [{len(allowed)} reviewed finding(s) hidden]"
        c.header(header)
        if not findings:
            c.say("  none")
        for i, f in enumerate(findings, 1):
            tag = c.badge(f.severity.upper(), SEVERITY_BADGE[f.severity])
            bar = c.paint(c.g["bar"], *SEVERITY_STYLE[f.severity]) if c.unicode else ""
            c.say(f"  {i}) {bar}{tag} {f.grade}")
            c.wrapped(describe_indicator(f), "      ", "      ", bar=bar)
            c.wrapped(f"where:  {f.location}", "      ", "              ", bar=bar)
            c.wrapped(f"detail: {f.detail}", "      ", "              ", bar=bar)
        if findings:
            c.wrapped(
                "To stop seeing a finding you have reviewed, use Reports -> Reviewed findings.",
                "  ", "  ", "grey",
            )

        gaps = report.gaps
        c.say()
        c.header(f"COULD NOT CHECK ({len(gaps)})", "yellow", "bold")
        if not gaps:
            c.say("  nothing was skipped")
        for name, text in gaps:
            c.wrapped(f"[{name}] {text}", "  - ", "    ", "yellow")
        c.say()
        c.wrapped(EXPERT_HELP, "  ", "  ", "grey")

    # ---- scanning ---------------------------------------------------------
    def scan_flow(self, quick: bool, only: Sequence[str], label: str) -> None:
        c = self.c
        if self.indicators is None:
            c.bad("No indicator feed is loaded. Open 'Indicator feeds' and switch one on, or load a CSV.")
            self.pause()
            return
        c.say()
        c.info(f"{label}: {', '.join(only)}")
        if "files" in only and not quick:
            c.info(f"Hashing file contents, up to {self.max_files:,} files per folder. This can take a few minutes. Ctrl-C cancels.")

        total = len(only)
        state = {"done": 0}
        started: dict = {}
        spinner = Spinner(c)

        def progress(event: str, name: str, result: Optional[CheckResult]) -> None:
            if event == "start":
                started[name] = time.monotonic()
                if c.interactive:
                    spinner.start(f"{name:<12} scanning...")
                else:
                    c.say(f"  {c.paint(c.g['info'], 'cyan', 'bold')} {name:<12} scanning...")
            elif result is not None:
                spinner.stop()
                state["done"] += 1
                took = time.monotonic() - started.get(name, time.monotonic())
                mark = c.paint(c.g["ok"], "green", "bold") if result.status == "ran" else c.paint(c.g["warn"], "yellow", "bold")
                bar = c.bar(state["done"], total, 10, "green")
                c.say(
                    f"  {mark} {name:<12} examined {result.examined:,}  findings {len(result.findings)}  "
                    f"gaps {len(result.gaps)}  {took:.1f}s  [{bar}] {state['done']}/{total}"
                )

        tick = None
        if c.interactive:
            def tick(n: int) -> None:
                spinner.update(f"files        {n:,} examined")

        try:
            report = run_scan(
                self.indicators, quick=quick, max_files=self.max_files, only=list(only), progress=progress, tick=tick,
                deep=self.deep,
            )
        except KeyboardInterrupt:
            spinner.stop()
            c.say()
            c.warn("Scan cancelled; nothing was kept.")
            self.pause()
            return
        self.report = report
        self.record_history(report)
        self.show_report(report)
        self.show_diff()
        self.show_baseline_diff()
        c.say()
        if c.ask("Save this report to disk? [y/N]").lower() in ("y", "yes"):
            self.save_report()
        self.pause()

    def custom_scan(self) -> None:
        c = self.c
        while True:
            c.say()
            c.say(c.paint("Checks (selected are marked [x])", "bold"))
            for i, name in enumerate(CHECK_NAMES, 1):
                mark = "[x]" if name in self.selected else "[ ]"
                c.say(f"  {i}) {mark} {name:<12} {c.paint(CHECK_INFO[name], 'grey')}")
            text = c.ask("Select checks: numbers or names, or 'all'. Enter keeps the current choice:")
            if not text:
                break
            try:
                self.selected = parse_selection(text, CHECK_NAMES)
                break
            except ValueError as exc:
                c.bad(str(exc))
        self.scan_flow(quick=not self.hash_files, only=list(self.selected), label="Custom scan")

    # ---- feed menu --------------------------------------------------------
    def choose_feeds(self) -> None:
        c = self.c
        if self.source_file is not None:
            c.warn("A CSV was loaded by hand. Choose 'Reload feeds' first to use the feeds folder.")
            return
        if not self.feeds:
            c.bad(f"No feed files found in {self.feeds_dir}")
            return
        changed = False
        while True:
            c.say()
            c.say(c.paint("Feeds (switched on are marked [x])", "bold"))
            self.print_feed_table()
            text = c.ask("Numbers or names to switch on/off, 'all', 'none'. Enter to finish:").lower()
            if not text:
                break
            if text == "all":
                self.disabled = set()
            elif text == "none":
                self.disabled = {f.name for f in self.feeds}
            else:
                try:
                    names = parse_feed_tokens(text, [f.name for f in self.feeds])
                except ValueError as exc:
                    c.bad(str(exc))
                    continue
                for name in names:
                    self.disabled ^= {name}
            changed = True
            for f in self.feeds:
                f.enabled = f.name not in self.disabled and not f.error
        if changed:
            error = save_disabled(self.feeds_dir, self.disabled)
            if error:
                c.bad(error)
            self._rebuild()
            if self.indicators is None:
                c.warn(f"Nothing is switched on: {self.feed_error}")
            else:
                c.good(f"{len(self.indicators):,} indicators are active")

    def feed_menu(self) -> None:
        c = self.c
        while True:
            c.say()
            if self.source_file is None and self.feeds:
                self.print_feed_table()
            if self.indicators is None:
                c.bad(f"No feed loaded: {self.feed_error}")
            else:
                counts = {}
                tiers = {}
                for ind in self.indicators.all():
                    counts[ind.kind] = counts.get(ind.kind, 0) + 1
                    tiers[ind.tier] = tiers.get(ind.tier, 0) + 1
                kinds = ", ".join(f"{n:,} {k}" for k, n in sorted(counts.items()))
                levels = ", ".join(f"{n:,} {t}" for t, n in sorted(tiers.items()))
                where = str(self.source_file) if self.source_file is not None else str(self.feeds_dir)
                c.info(where)
                c.info(f"{len(self.indicators):,} indicators active: {kinds}  ({levels})")
                if is_placeholder(self.indicators):
                    c.warn("This is the placeholder test feed, not real indicators.")
            key = self.menu(
                "INDICATOR FEEDS",
                [
                    ("1", "Load a CSV", "this session only; replaces the feeds"),
                    ("2", "Show indicators", "first 25, defanged"),
                    ("3", "Choose feeds", "switch campaigns on or off"),
                    ("4", "Reload feeds", "re-read the iocs folder"),
                    ("0", "Back", ""),
                ],
                crumb="feeds",
            )
            if key == "0":
                return
            if key == "1":
                raw = c.ask("Path to indicator CSV:").strip().strip('"').strip("'")
                if not raw:
                    continue
                error = self.load_feed(Path(raw).expanduser())
                if error:
                    c.bad(error)
                    c.info("The previously loaded feed (if any) is unchanged.")
                else:
                    c.good(f"Loaded {len(self.indicators):,} indicators from {self.source_file.name}")
            elif key == "2":
                if self.indicators is None:
                    c.bad("Nothing loaded.")
                    continue
                for ind in self.indicators.all()[:25]:
                    c.say(f"  {ind.kind:<9}{defang(ind.value, ind.kind):<44} {ind.tier}")
                self.pause()
            elif key == "3":
                self.choose_feeds()
            elif key == "4":
                self.reload_feeds()
                if self.indicators is None:
                    c.bad(f"No feed loaded: {self.feed_error}")
                else:
                    c.good(f"{len(self.indicators):,} indicators active from {sum(1 for f in self.feeds if f.enabled)} feeds")

    # ---- history ----------------------------------------------------------
    @property
    def history_dir(self) -> Path:
        return self.reports_dir / "history"

    def record_history(self, report: ScanReport) -> None:
        previous = history.load_latest(self.history_dir)
        self.diff = history.compare(previous, report) if previous else None
        try:
            history.save(self.history_dir, report)
        except OSError as exc:
            self.c.warn(f"Could not record this scan in the history ({exc.__class__.__name__}); comparisons will be missing.")

    def show_diff(self) -> None:
        c = self.c
        d = self.diff
        if d is None:
            c.say()
            c.info("First recorded scan: the next one will show what changed.")
            return
        c.say()
        c.say(c.paint(f"CHANGES SINCE {d.previous_started}", "bold"))
        if not d.new and not d.resolved:
            c.good(f"No change in findings ({d.unchanged} unchanged).")
        for f in d.new:
            c.bad(f"NEW      [{f.severity}] {f.check}: {f.indicator.kind} {f.indicator.value}  {f.location}")
        for item in d.resolved:
            c.good(f"RESOLVED [{item['severity']}] {item['check']}: {item['kind']} {item['value']}  {item['location']}")
        if d.unchanged and (d.new or d.resolved):
            c.info(f"{d.unchanged} finding(s) unchanged.")
        if d.not_compared:
            c.warn(f"Not compared (check did not run this time): {', '.join(d.not_compared)}")

    def show_baseline_diff(self) -> None:
        c = self.c
        data = baseline.load(self.reports_dir)
        if data is None:
            c.say()
            c.info("No baseline set. Reports -> Baseline lets you record one on a clean day, "
                    "so a later scan can flag anything new even if it matches no feed.")
            return
        diff = baseline.compare(data, self.report)
        c.say()
        c.say(c.paint(f"NEW SINCE BASELINE ({data.get('created', 'unknown')})", "bold", "yellow"))
        if not diff.new:
            c.good("Nothing new in the autostart / listener surface since the baseline.")
        for check, location, detail in diff.new:
            c.wrapped(f"[{check}] {location}: {detail}", "  - ", "    ", "yellow")
        if diff.new:
            c.wrapped(
                "This is not evidence of infection by itself: a software update or a new install "
                "shows up here too. It means the item was not present when the baseline was set.",
                "  ", "  ", "grey",
            )
        if diff.not_covered:
            c.warn(f"Not compared (check did not run this time): {', '.join(diff.not_covered)}")

    def baseline_menu(self) -> None:
        c = self.c
        while True:
            data = baseline.load(self.reports_dir)
            c.say()
            if data is None:
                c.say(c.paint("BASELINE: none set", "bold"))
            else:
                c.say(c.paint(f"BASELINE: set {data.get('created', 'unknown')}  ({len(data.get('items', []))} item(s))", "bold"))
            c.say(f"  covers: {', '.join(baseline.INVENTORY_CHECKS)}")
            key = self.menu(
                "BASELINE",
                [
                    ("1", "Set from last scan", "replaces any existing baseline"),
                    ("2", "Show what is new now", "compares the last scan to the baseline"),
                    ("0", "Back", ""),
                ],
                crumb="baseline",
            )
            if key == "0":
                return
            if key == "1":
                if self.report is None:
                    c.warn("There is no scan yet. Run one from the main menu first.")
                    continue
                missing = [n for n in baseline.INVENTORY_CHECKS if n not in {r.name for r in self.report.results if r.status == "ran"}]
                if missing:
                    c.warn(f"The last scan did not run: {', '.join(missing)}. Baselining it anyway, "
                           f"but those checks will show as not covered until a scan runs them.")
                err = baseline.set_baseline(self.reports_dir, self.report)
                if err:
                    c.bad(err)
                else:
                    c.good("Baseline set from the last scan.")
            elif key == "2":
                if self.report is None:
                    c.warn("There is no scan yet. Run one from the main menu first.")
                else:
                    self.show_baseline_diff()
                    self.pause()

    # ---- reports ----------------------------------------------------------
    def save_report(self) -> None:
        c = self.c
        if self.report is None:
            c.warn("There is no scan to save yet.")
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        try:
            self.reports_dir.mkdir(parents=True, exist_ok=True)
            text_path = self.reports_dir / f"argus-{stamp}.txt"
            json_path = self.reports_dir / f"argus-{stamp}.json"
            html_path = self.reports_dir / f"argus-{stamp}.html"
            text_path.write_text(render_text(self.report), encoding="utf-8")
            json_path.write_text(json.dumps(self.report.to_dict(), indent=2), encoding="utf-8")
            html_path.write_text(render_html(self.report), encoding="utf-8")
        except OSError as exc:
            c.bad(f"Could not save the report: {exc}")
            return
        self.last_html = html_path
        for path in (text_path, json_path, html_path):
            c.good(f"Saved {path}")
        c.warn("Reports contain file paths and, in the JSON, raw indicator values. Share them carefully.")

    def list_reports(self) -> None:
        c = self.c
        try:
            files = sorted(self.reports_dir.glob("argus-*.txt"), reverse=True)[:15]
        except OSError:
            files = []
        if not files:
            c.info(f"No saved reports in {self.reports_dir}")
            return
        c.info(f"Saved reports in {self.reports_dir} (newest first):")
        for f in files:
            c.say(f"  {f.name}  {f.stat().st_size:,} bytes")

    def latest_html(self) -> Optional[Path]:
        if self.last_html is not None and self.last_html.is_file():
            return self.last_html
        try:
            files = sorted(self.reports_dir.glob("argus-*.html"), reverse=True)
        except OSError:
            return None
        return files[0] if files else None

    def open_html(self) -> None:
        c = self.c
        path = self.latest_html()
        if path is None:
            c.warn("No HTML report yet. Save a scan first (option 2).")
            return
        try:
            opened = webbrowser.open(path.resolve().as_uri())
        except Exception:
            opened = False
        if opened:
            c.good(f"Opened {path} in your browser")
        else:
            c.warn(f"Could not start a browser. Open this file yourself: {path}")

    def reports_menu(self) -> None:
        c = self.c
        while True:
            key = self.menu(
                "REPORTS",
                [
                    ("1", "View last scan", ""),
                    ("2", "Save last scan", "text, JSON and HTML"),
                    ("3", "List saved", ""),
                    ("4", "Open HTML report", "in your browser"),
                    ("5", "Changes since previous scan", "new and resolved findings"),
                    ("6", "Reviewed findings", "mark a finding as reviewed, or un-mark it"),
                    ("7", "Baseline", "flag items new since a clean-day snapshot"),
                    ("0", "Back", ""),
                ],
                crumb="reports",
            )
            if key == "0":
                return
            if key == "1":
                if self.report is None:
                    c.warn("There is no scan yet. Run one from the main menu.")
                else:
                    self.show_report(self.report)
                    self.pause()
            elif key == "2":
                self.save_report()
            elif key == "3":
                self.list_reports()
            elif key == "4":
                self.open_html()
            elif key == "5":
                if self.report is None:
                    c.warn("There is no scan yet. Run one from the main menu.")
                else:
                    self.show_diff()
                    self.pause()
            elif key == "6":
                self.allowlist_menu()
            elif key == "7":
                self.baseline_menu()

    def allowlist_menu(self) -> None:
        c = self.c
        while True:
            entries = sorted(self.allowlist.values(), key=lambda e: e.key)
            c.say()
            c.say(c.paint(f"REVIEWED FINDINGS ({len(entries)})", "bold"))
            if not entries:
                c.say("  none yet")
            for i, e in enumerate(entries, 1):
                check, grade, kind, value, location = e.key
                note = f"  -- {e.note}" if e.note else ""
                c.say(f"  {i}) [{check}/{grade}] {kind} {value}  ({location}){note}")
            c.say()
            c.say("  a) add from the last scan's findings     r <n>) remove entry n     0) back")
            choice = c.ask("reports/reviewed>").strip().lower()
            if choice in ("0", ""):
                return
            if choice == "a":
                self._allowlist_add_flow()
                continue
            if choice.startswith("r"):
                rest = choice[1:].strip()
                if rest.isdigit() and 1 <= int(rest) <= len(entries):
                    allowlist.remove(self.reports_dir, entries[int(rest) - 1].key)
                    self.reload_allowlist()
                    c.good("Removed.")
                else:
                    c.bad("Give the number shown next to the entry, e.g. 'r 1'.")
                continue
            c.bad("Enter 'a', 'r <n>', or 0.")

    def _allowlist_add_flow(self) -> None:
        c = self.c
        if self.report is None:
            c.warn("There is no scan yet. Run one from the main menu first.")
            return
        visible, _allowed = allowlist.split(self.report, self.allowlist)
        if not visible:
            c.info("Nothing to mark: the last scan has no (unreviewed) findings.")
            return
        for i, f in enumerate(visible, 1):
            c.say(f"  {i}) [{f.severity}] {f.check}/{f.grade}  {f.indicator.kind} {defang(f.indicator.value, f.indicator.kind)}  ({f.location})")
        choice = c.ask("Mark which number as reviewed? (Enter cancels)").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(visible)):
            return
        finding = visible[int(choice) - 1]
        note = c.ask("Note (why this is not a concern; optional):")
        allowlist.add(self.reports_dir, finding, note)
        self.reload_allowlist()
        c.good("Marked as reviewed. It will be hidden from future reports of this exact finding.")

    # ---- settings / about -------------------------------------------------
    def settings_menu(self) -> None:
        c = self.c
        while True:
            c.say()
            c.say(c.paint("CURRENT STATE", "bold"))
            on_feeds = sum(1 for f in self.feeds if f.enabled and not f.error) if self.feeds else 0
            feed_line = (
                f"single file: {self.source_file.name}" if self.source_file is not None
                else f"{on_feeds} of {len(self.feeds)} feeds switched on"
            )
            baseline_state = baseline.load(self.reports_dir)
            c.say(f"  indicators   {len(self.indicators):,} active ({feed_line})" if self.indicators is not None else "  indicators   none loaded")
            c.say(f"  reviewed     {len(self.allowlist)} finding(s) marked reviewed  (Reports -> 6)")
            c.say(
                f"  baseline     set {baseline_state['created']}  ({len(baseline_state.get('items', []))} item(s))  (Reports -> 7)"
                if baseline_state else "  baseline     not set  (Reports -> 7)"
            )
            c.say(f"  checks       {len(self.selected)} of {len(CHECK_NAMES)} selected for a Custom scan  (menu 3, or 8 for detail)")
            key = self.menu(
                "SETTINGS",
                [
                    ("1", f"Files per folder: {self.max_files:,}", "limit for the files check"),
                    ("2", f"Hash contents: {'on' if self.hash_files else 'off'}", "applies to custom scans"),
                    ("3", f"Colour: {'on' if c.color else 'off'}", "toggle ANSI colours"),
                    ("4", f"Deep file scan: {'on' if self.deep else 'off'}", "include cache and dependency folders"),
                    ("5", f"Fancy symbols: {'on' if c.unicode else 'off'}", "boxes and icons; off = plain ASCII"),
                    ("0", "Back", ""),
                ],
                crumb="settings",
            )
            if key == "0":
                return
            if key == "1":
                raw = c.ask("Files to examine per folder (100 to 1,000,000):").replace(",", "")
                if raw.isdigit() and 100 <= int(raw) <= 1_000_000:
                    self.max_files = int(raw)
                    c.good(f"Files per folder set to {self.max_files:,}")
                else:
                    c.bad("Enter a whole number from 100 to 1,000,000.")
            elif key == "2":
                self.hash_files = not self.hash_files
                c.good(f"Hash contents is now {'on' if self.hash_files else 'off'}")
            elif key == "3":
                c.color = not c.color
                c.good(f"Colour is now {'on' if c.color else 'off'}")
            elif key == "5":
                c.unicode = not c.unicode
                c.good(f"Fancy symbols are now {'on' if c.unicode else 'off'}")
            elif key == "4":
                self.deep = not self.deep
                c.good(f"Deep file scan is now {'on' if self.deep else 'off'}")

    def checks_screen(self) -> None:
        c = self.c
        last = {r.name: r for r in self.report.results} if self.report is not None else {}
        c.say()
        c.say(c.paint(f"CHECKS ({len(CHECK_NAMES)})", "bold"))
        for i, name in enumerate(CHECK_NAMES, 1):
            selected = c.paint("x", "green", "bold") if name in self.selected else " "
            c.say(f"  {i:>2}) [{selected}] {c.paint(name, 'bold'):<13}  {c.paint(CHECK_PLATFORMS[name], 'grey')}")
            c.wrapped(CHECK_INFO[name], "        ", "        ", "grey")
            r = last.get(name)
            if r is None:
                c.say(c.paint("        last scan: did not run", "grey"))
            else:
                detail = f"last scan: {r.status}, examined {r.examined:,}, {len(r.findings)} finding(s)"
                if r.note:
                    detail += f"  ({r.note})"
                c.say(c.paint(f"        {detail}", "grey"))
        c.say()
        c.say(c.paint("[x] marks a check that is part of the current custom-scan selection "
                       "(change it from the main menu's Custom scan).", "grey"))
        self.pause()

    def about(self) -> None:
        c = self.c
        c.say()
        c.sigil()
        c.say()
        c.box(
            [
                f"ARGUS {__version__}",
                "",
                "Read-only, offline check of this computer for published indicators of compromise.",
                "",
                "It never contacts the network (the socket layer is blocked while it runs), never "
                "modifies the system, and reads cookie host names and times only, never values.",
                "",
                "A clean result is not a clean bill of health. Every report lists what could not "
                "be checked. Matches are leads that need interpretation, not proof of infection.",
                "",
                "Developed by Salim, Tunisia.",
            ],
            "cyan",
        )
        c.wrapped(EXPERT_HELP, "  ", "  ", "grey")
        self.pause()

    # ---- main loop --------------------------------------------------------
    def reload_allowlist(self) -> None:
        self.allowlist = allowlist.load(self.reports_dir)

    def intro(self) -> None:
        """A short start-up sequence on a real terminal. Skipped when output is piped or tested."""
        c = self.c
        if not c.interactive:
            return
        n = len(self.indicators) if self.indicators is not None else 0
        steps = [
            "arming network lock ...... sockets and DNS disabled",
            f"loading indicators ....... {n:,} loaded" if n else "loading indicators ....... none loaded",
            "mode ..................... read-only, nothing is written to the system",
        ]
        c.clear()
        for line in steps:
            c.typed(f"  {c.g['ok']} {line}", 0.006, "red")
            time.sleep(0.12)
        c.say()
        c.sigil()
        c.say()
        c.typed(random.choice(MANIFESTO_LINES).center(c.width), 0.01, "grey")
        time.sleep(0.4)

    def run(self) -> int:
        netguard.install()
        if self.source_file is not None:
            self.feed_error = self.load_feed(self.source_file)
        else:
            self.reload_feeds()
        try:
            self.reload_allowlist()
            self.intro()
            while True:
                self.show_header()
                key = self.menu("MAIN MENU", MAIN_ITEMS, accent=self.status_accent())
                if key == "0":
                    break
                if key == "1":
                    self.scan_flow(quick=False, only=list(CHECK_NAMES), label="Full scan")
                elif key == "2":
                    self.scan_flow(quick=True, only=list(CHECK_NAMES), label="Quick scan")
                elif key == "3":
                    self.custom_scan()
                elif key == "4":
                    self.feed_menu()
                elif key == "5":
                    self.reports_menu()
                elif key == "6":
                    self.settings_menu()
                elif key == "7":
                    self.about()
                elif key == "8":
                    self.checks_screen()
        except (EOFError, KeyboardInterrupt):
            self.c.say()
        self.c.say(self.c.paint("Goodbye.", "grey"))
        return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        from .__main__ import main as cli_main

        return cli_main(args)
    safe_console()
    return App(Console()).run()
