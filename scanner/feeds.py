"""Feed discovery: one CSV per campaign in iocs/, switched on or off in iocs/feeds.json."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from .ioc import IOCError, Indicator, IndicatorSet, load_indicators, merge_indicators

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FEEDS_DIR = PROJECT_ROOT / "iocs"
NOT_FEEDS = {"sample", "unverified-candidates"}
CONFIG_NAME = "feeds.json"
OFF_BY_DEFAULT_PREFIX = "phishing-"  # phishing-only lists are not spyware; off until the user turns them on


@dataclass
class Feed:
    name: str
    path: Path
    indicators: List[Indicator] = field(default_factory=list, repr=False)
    error: Optional[str] = None
    enabled: bool = True

    @property
    def count(self) -> int:
        return len(self.indicators)

    @property
    def kinds(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for ind in self.indicators:
            out[ind.kind] = out.get(ind.kind, 0) + 1
        return out


def load_disabled(directory: Path) -> Set[str]:
    """Names switched off. With no readable config, phishing-only lists start off."""
    config = Path(directory) / CONFIG_NAME
    try:
        data = json.loads(config.read_text(encoding="utf-8"))
        names = data["disabled"]
        if isinstance(names, list) and all(isinstance(n, str) for n in names):
            return set(names)
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return {p.stem for p in Path(directory).glob(f"{OFF_BY_DEFAULT_PREFIX}*.csv")}


def save_disabled(directory: Path, names: Set[str]) -> Optional[str]:
    """Returns an error message, or None on success."""
    try:
        (Path(directory) / CONFIG_NAME).write_text(
            json.dumps({"disabled": sorted(names)}, indent=2) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        return f"could not save {CONFIG_NAME}: {exc}"
    return None


def discover_feeds(directory: Path, disabled: Optional[Set[str]] = None) -> List[Feed]:
    directory = Path(directory)
    off = load_disabled(directory) if disabled is None else disabled
    feeds: List[Feed] = []
    try:
        paths = sorted(p for p in directory.glob("*.csv") if p.stem not in NOT_FEEDS)
    except OSError:
        paths = []
    for path in paths:
        feed = Feed(name=path.stem, path=path, enabled=path.stem not in off)
        try:
            feed.indicators = load_indicators(path)
        except IOCError as exc:
            feed.error = str(exc)
            feed.enabled = False
        feeds.append(feed)
    return feeds


def build_set(feeds: List[Feed]) -> Optional[IndicatorSet]:
    """Merge every enabled, readable feed. None when nothing is switched on."""
    lists = [f.indicators for f in feeds if f.enabled and not f.error]
    if not lists:
        return None
    return IndicatorSet(merge_indicators(lists))
