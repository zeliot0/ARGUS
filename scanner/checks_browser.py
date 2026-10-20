"""Browser history and cookie metadata.

Only host names and timestamps are read, never cookie values. Each database is copied to
a temp folder before reading, so a running browser's lock is never touched.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlsplit

from .evidence import CheckResult, make_finding
from .fsutil import copy_file
from .ioc import IndicatorSet

CHROME_HISTORY_SQL = "SELECT url, last_visit_time FROM urls"
CHROME_COOKIE_SQL = "SELECT host_key, last_access_utc FROM cookies"
FIREFOX_HISTORY_SQL = "SELECT url, last_visit_date FROM moz_places WHERE url IS NOT NULL"
FIREFOX_COOKIE_SQL = "SELECT host, lastAccessed FROM moz_cookies"

_EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
_UTC = timezone.utc


def chromium_time(value: Optional[int]) -> Optional[str]:
    """Chromium stores microseconds since 1601-01-01 UTC."""
    if not value or value <= 0:
        return None
    try:
        return (_EPOCH_1601 + timedelta(microseconds=int(value))).isoformat()
    except (OverflowError, ValueError):
        return None


def firefox_time(value: Optional[int]) -> Optional[str]:
    """Firefox stores microseconds since the Unix epoch."""
    if not value or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value / 1_000_000, tz=_UTC).isoformat()
    except (OverflowError, ValueError, OSError):
        return None


@dataclass(frozen=True)
class BrowserDB:
    browser: str
    profile: str
    engine: str  # "chromium" | "firefox"
    kind: str  # "history" | "cookies"
    path: Path


def browser_roots(home: Optional[Path] = None, platform: Optional[str] = None) -> List[Tuple[str, str, Path]]:
    home = Path(home) if home else Path.home()
    platform = platform or sys.platform
    if platform == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        roaming = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        chromium = {
            "Chrome": local / "Google" / "Chrome" / "User Data",
            "Edge": local / "Microsoft" / "Edge" / "User Data",
            "Brave": local / "BraveSoftware" / "Brave-Browser" / "User Data",
            "Chromium": local / "Chromium" / "User Data",
        }
        firefox_root = roaming / "Mozilla" / "Firefox" / "Profiles"
    elif platform == "darwin":
        support = home / "Library" / "Application Support"
        chromium = {
            "Chrome": support / "Google" / "Chrome",
            "Edge": support / "Microsoft Edge",
            "Brave": support / "BraveSoftware" / "Brave-Browser",
            "Chromium": support / "Chromium",
        }
        firefox_root = support / "Firefox" / "Profiles"
    else:
        cfg = home / ".config"
        chromium = {
            "Chrome": cfg / "google-chrome",
            "Edge": cfg / "microsoft-edge",
            "Brave": cfg / "BraveSoftware" / "Brave-Browser",
            "Chromium": cfg / "chromium",
        }
        firefox_root = home / ".mozilla" / "firefox"
    roots = [(name, "chromium", path) for name, path in chromium.items()]
    roots.append(("Firefox", "firefox", firefox_root))
    return roots


def discover(roots: List[Tuple[str, str, Path]]) -> Tuple[List[BrowserDB], List[str]]:
    found: List[BrowserDB] = []
    problems: List[str] = []
    for browser, engine, root in roots:
        if not root.is_dir():
            continue
        try:
            profiles = sorted(p for p in root.iterdir() if p.is_dir())
        except OSError as exc:
            problems.append(f"{browser}: cannot list {root} ({exc.__class__.__name__})")
            continue
        for profile in profiles:
            if engine == "chromium":
                history = profile / "History"
                if history.is_file():
                    found.append(BrowserDB(browser, profile.name, engine, "history", history))
                for candidate in (profile / "Network" / "Cookies", profile / "Cookies"):
                    if candidate.is_file():
                        found.append(BrowserDB(browser, profile.name, engine, "cookies", candidate))
                        break
            else:
                places = profile / "places.sqlite"
                if places.is_file():
                    found.append(BrowserDB(browser, profile.name, engine, "history", places))
                cookies = profile / "cookies.sqlite"
                if cookies.is_file():
                    found.append(BrowserDB(browser, profile.name, engine, "cookies", cookies))
    return found, problems


_SQL = {
    ("chromium", "history"): CHROME_HISTORY_SQL,
    ("chromium", "cookies"): CHROME_COOKIE_SQL,
    ("firefox", "history"): FIREFOX_HISTORY_SQL,
    ("firefox", "cookies"): FIREFOX_COOKIE_SQL,
}


def _read_rows(db: BrowserDB, workdir: Path) -> Iterator[Tuple[Optional[str], Optional[int]]]:
    dest_dir = Path(tempfile.mkdtemp(dir=workdir))
    dest = dest_dir / db.path.name
    copy_file(db.path, dest)
    for suffix in ("-wal", "-journal"):
        side = db.path.with_name(db.path.name + suffix)
        if side.is_file():
            try:
                copy_file(side, dest_dir / side.name)
            except OSError:
                pass  # a missing or locked journal only means recent rows may be absent
    conn = sqlite3.connect(str(dest))
    try:
        for row in conn.execute(_SQL[(db.engine, db.kind)]):
            yield row[0], row[1]
    finally:
        conn.close()


def _host_for_row(db: BrowserDB, value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    if db.kind == "history":
        try:
            return urlsplit(value).hostname
        except ValueError:
            return None
    return value


def _timestamp(db: BrowserDB, stamp: Optional[int]) -> Optional[str]:
    return chromium_time(stamp) if db.engine == "chromium" else firefox_time(stamp)


def check_browsers(indicators: IndicatorSet, home: Optional[Path] = None, platform: Optional[str] = None) -> CheckResult:
    result = CheckResult("browser")
    found, problems = discover(browser_roots(home, platform))
    result.gaps.extend(problems)
    if not found:
        result.gaps.append("no supported browser profiles were found; nothing was read")
        return result

    hits: Dict[tuple, dict] = {}
    with tempfile.TemporaryDirectory(prefix="scan-browser-") as tmp:
        workdir = Path(tmp)
        for db in found:
            try:
                for raw_value, stamp in _read_rows(db, workdir):
                    result.examined += 1
                    host = _host_for_row(db, raw_value)
                    if not host:
                        continue
                    ind = indicators.find_endpoint(host)
                    if ind is None:
                        continue
                    grade = "visit" if db.kind == "history" else "cookie-lead"
                    entry = hits.setdefault(
                        (db.browser, db.profile, grade, ind.value),
                        {"count": 0, "last": None, "host": host, "ind": ind},
                    )
                    entry["count"] += 1
                    ts = _timestamp(db, stamp)
                    if ts and (entry["last"] is None or ts > entry["last"]):
                        entry["last"] = ts
            except (sqlite3.Error, OSError) as exc:
                result.gaps.append(
                    f"{db.browser} {db.profile} {db.kind}: unreadable ({exc.__class__.__name__}); "
                    "the browser may be holding it locked, so close the browser and scan again"
                )

    for (browser, profile, grade, _value), entry in hits.items():
        when = entry["last"] or "unknown time"
        if grade == "visit":
            detail = f"{entry['count']} history entries for {entry['host']}; last at {when}"
        else:
            detail = f"{entry['count']} cookie records for {entry['host']} (host and time only); last access {when}"
        result.findings.append(
            make_finding("browser", grade, entry["ind"], f"{browser} / {profile}", detail)
        )
    return result
