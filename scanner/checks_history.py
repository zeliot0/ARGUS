"""Shell and PowerShell command history, scanned as plain text.

A hit here is weak evidence (the line could be a typo, or a command that never ran), so
it never goes above "low" severity.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .evidence import CheckResult, make_finding
from .ioc import IndicatorSet

_MAX_BYTES = 10 * 1024 * 1024
_MAX_LINE = 400
# Domain/IP-shaped runs anywhere in the line; file names are matched separately below.
_HOST_TOKEN = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")
_WORD_SPLIT = re.compile(r"[^A-Za-z0-9_.-]+")


def history_files(home: Optional[Path] = None, platform: Optional[str] = None) -> List[Path]:
    home = Path(home) if home else Path.home()
    platform = platform or sys.platform
    candidates = [home / ".bash_history", home / ".zsh_history", home / ".sh_history", home / ".local" / "share" / "fish" / "fish_history"]
    if platform == "win32":
        import os

        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        candidates.append(appdata / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt")
    return [p for p in candidates if p.is_file()]


def _lines(path: Path) -> Iterable[str]:
    try:
        if path.stat().st_size > _MAX_BYTES:
            return
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for line in text.splitlines():
        yield line[:_MAX_LINE]


def check_history(
    indicators: IndicatorSet,
    home: Optional[Path] = None,
    platform: Optional[str] = None,
    paths: Optional[List[Path]] = None,
) -> CheckResult:
    result = CheckResult("history")
    files = paths if paths is not None else history_files(home, platform)
    if not files:
        result.gaps.append("no shell or PowerShell history file was found")
        return result

    unreadable: List[str] = []
    hits = {}  # (path, indicator key) -> count
    for path in files:
        examined_any = False
        try:
            lines = list(_lines(path))
        except OSError:
            unreadable.append(str(path))
            continue
        for line in lines:
            examined_any = True
            result.examined += 1
            lowered = line.lower()
            matched = set()
            for match in _HOST_TOKEN.finditer(lowered):
                ind = indicators.find_endpoint(match.group(0))
                if ind is not None:
                    matched.add((ind.kind, ind.value))
            for word in _WORD_SPLIT.split(lowered):
                word = word.strip(".-")
                if not word:
                    continue
                ind = indicators.by_kind("filename").get(word)
                if ind is not None:
                    matched.add((ind.kind, ind.value))
            for kind, value in matched:
                key = (str(path), kind, value)
                hits[key] = hits.get(key, 0) + 1
        if not examined_any:
            continue

    seen = set()
    for (path, kind, value), count in hits.items():
        for ind in indicators.by_kind(kind).values():
            if ind.value == value and (path, kind, value) not in seen:
                seen.add((path, kind, value))
                result.findings.append(
                    make_finding("history", "shell-history", ind, path, f"{count} matching line(s) in the history file")
                )
                break
    if unreadable:
        result.gaps.append(f"could not read: {', '.join(unreadable)}")
    result.gaps.append("a history entry is weak evidence: the command may not have run or succeeded")
    return result
