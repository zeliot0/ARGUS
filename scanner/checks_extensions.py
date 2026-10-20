"""Installed browser extensions, matched by ID and by manifest name.

Chromium extensions are matched by their folder ID; Firefox add-ons by the ID in their
install manifest. Only metadata is read; extension code itself is never run or opened.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .checks_browser import browser_roots
from .evidence import CheckResult, make_finding
from .ioc import IndicatorSet

_MAX_NAME = 120


def _chromium_extensions(root: Path) -> List[Tuple[str, str, str]]:
    """(profile, extension_id, display_name) for every unpacked extension under root."""
    out: List[Tuple[str, str, str]] = []
    if not root.is_dir():
        return out
    try:
        profiles = sorted(p for p in root.iterdir() if p.is_dir())
    except OSError:
        return out
    for profile in profiles:
        ext_dir = profile / "Extensions"
        if not ext_dir.is_dir():
            continue
        try:
            ext_ids = sorted(p for p in ext_dir.iterdir() if p.is_dir())
        except OSError:
            continue
        for ext_id in ext_ids:
            name = ""
            try:
                versions = sorted(p for p in ext_id.iterdir() if p.is_dir())
            except OSError:
                versions = []
            for version in versions:
                manifest = version / "manifest.json"
                if manifest.is_file():
                    try:
                        data = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
                        name = str(data.get("name", ""))[:_MAX_NAME]
                    except (OSError, ValueError):
                        pass
                    break
            out.append((profile.name, ext_id.name.lower(), name))
    return out


def _firefox_extensions(root: Path) -> List[Tuple[str, str, str]]:
    out: List[Tuple[str, str, str]] = []
    if not root.is_dir():
        return out
    try:
        profiles = sorted(p for p in root.iterdir() if p.is_dir())
    except OSError:
        return out
    for profile in profiles:
        path = profile / "extensions.json"
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        for item in data.get("addons", []) if isinstance(data, dict) else []:
            if not isinstance(item, dict):
                continue
            ext_id = str(item.get("id", "")).lower()
            name = str(item.get("defaultLocale", {}).get("name", "") if isinstance(item.get("defaultLocale"), dict) else "")
            out.append((profile.name, ext_id, name[:_MAX_NAME]))
    return out


def check_extensions(
    indicators: IndicatorSet,
    home: Optional[Path] = None,
    platform: Optional[str] = None,
) -> CheckResult:
    result = CheckResult("extensions")
    ids = indicators.by_kind("extension")
    names = indicators.by_kind("filename")
    found: List[Tuple[str, str, str, str]] = []  # browser, profile, id, name
    for browser, engine, root in browser_roots(home, platform):
        if engine == "chromium":
            found.extend((browser, profile, ext_id, name) for profile, ext_id, name in _chromium_extensions(root))
        else:
            found.extend((browser, profile, ext_id, name) for profile, ext_id, name in _firefox_extensions(root))

    if not found:
        result.gaps.append("no browser extensions were found to check")
        return result

    result.examined = len(found)
    for browser, profile, ext_id, name in found:
        ind = ids.get(ext_id) if ext_id else None
        grade_detail = f"installed extension ID {ext_id or '(unknown)'}"
        if ind is None and name:
            match = names.get(name.strip().lower())
            if match is not None:
                ind = match
                grade_detail = f'installed extension named "{name}" matches a campaign name; the name alone is weak evidence'
        if ind is not None:
            result.findings.append(
                make_finding("extensions", "extension" if ind.kind == "extension" else "name-lead",
                             ind, f"{browser} / {profile}", grade_detail)
            )
    result.gaps.append("only installed extensions are listed; disabled or removed ones are not seen")
    return result
