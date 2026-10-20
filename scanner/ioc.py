"""Indicator loading, validation and matching.

Indicator file format (CSV, UTF-8, '#' starts a comment line):

    kind,value,tier,confidence,source

kind        domain | ip | sha256 | filename | extension
tier        confirmed | lead   ("lead" = legitimate software abused by the campaign,
                                 reported as an investigation lead, never as proof)
confidence  free text, e.g. high / medium
source      citation for the indicator; every indicator must carry one
"""
from __future__ import annotations

import csv
import ipaddress
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

KINDS = ("domain", "ip", "sha256", "filename", "extension")
TIERS = ("confirmed", "lead")
REQUIRED_COLUMNS = ("kind", "value", "tier", "confidence", "source")

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_EXTENSION_ID_RE = re.compile(r"^[a-p]{32}$")  # Chromium extension IDs; Firefox IDs are free text
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")


class IOCError(ValueError):
    """The indicator file is missing, malformed, or contains an invalid value."""


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str
    tier: str
    confidence: str
    source: str
    campaign: str = ""


def normalize_host(host: str) -> str:
    return host.strip().strip(".").lower()


def normalize_value(kind: str, raw: str) -> str:
    value = raw.strip()
    if kind == "domain":
        host = normalize_host(value)
        if not _DOMAIN_RE.match(host):
            raise IOCError(f"invalid domain {raw!r}")
        return host
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise IOCError(f"invalid IP address {raw!r}") from None
    if kind == "sha256":
        lowered = value.lower()
        if not _HASH_RE.match(lowered):
            raise IOCError(f"invalid SHA-256 {raw!r}")
        return lowered
    if kind == "filename":
        if not value or "/" in value or "\\" in value:
            raise IOCError(f"filename must be a bare name, got {raw!r}")
        return value.lower()
    if kind == "extension":
        lowered = value.lower()
        if not lowered:
            raise IOCError("extension id must not be empty")
        return lowered
    raise IOCError(f"unknown kind {kind!r}")


def load_indicators(path: Union[str, Path]) -> List[Indicator]:
    source_path = Path(path)
    try:
        text = source_path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise IOCError(f"cannot read {source_path}: {exc}") from exc

    lines = (ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#"))
    reader = csv.DictReader(lines)
    missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
    if missing:
        raise IOCError(f"missing columns: {', '.join(missing)}")

    indicators: List[Indicator] = []
    seen = set()
    for row in reader:
        line_no = reader.line_num
        kind = (row.get("kind") or "").strip().lower()
        tier = (row.get("tier") or "").strip().lower()
        if kind not in KINDS:
            raise IOCError(f"line {line_no}: unknown kind {kind!r}")
        if tier not in TIERS:
            raise IOCError(f"line {line_no}: unknown tier {tier!r}")
        try:
            value = normalize_value(kind, row.get("value") or "")
        except IOCError as exc:
            raise IOCError(f"line {line_no}: {exc}") from None
        if (kind, value) in seen:
            continue
        seen.add((kind, value))
        indicators.append(
            Indicator(
                kind=kind,
                value=value,
                tier=tier,
                confidence=(row.get("confidence") or "").strip(),
                source=(row.get("source") or "").strip(),
                campaign=source_path.stem,
            )
        )
    if not indicators:
        raise IOCError("no indicators in file")
    return indicators


class IndicatorSet:
    """Fast lookup by kind. Domain lookups match the name and its parent domains."""

    def __init__(self, indicators: Iterable[Indicator]):
        self._by_kind: Dict[str, Dict[str, Indicator]] = {k: {} for k in KINDS}
        for ind in indicators:
            self._by_kind[ind.kind][ind.value] = ind

    def get(self, kind: str, value: str) -> Optional[Indicator]:
        return self._by_kind[kind].get(value)

    def by_kind(self, kind: str) -> Dict[str, Indicator]:
        return self._by_kind[kind]

    def find_host(self, host: str) -> Optional[Indicator]:
        """Match 'a.evil.example' against 'evil.example' but never 'notevil.example'."""
        labels = normalize_host(host).split(".")
        domains = self._by_kind["domain"]
        for i in range(len(labels) - 1):
            ind = domains.get(".".join(labels[i:]))
            if ind is not None:
                return ind
        return None

    def __len__(self) -> int:
        return sum(len(v) for v in self._by_kind.values())

    def all(self) -> List[Indicator]:
        return [ind for kind in KINDS for ind in self._by_kind[kind].values()]

    def find_endpoint(self, host: str) -> Optional[Indicator]:
        """An IP literal is matched against IP indicators, a name against domain indicators."""
        text = host.strip().strip("[]")
        try:
            ip = str(ipaddress.ip_address(text))
        except ValueError:
            return self.find_host(host)
        return self._by_kind["ip"].get(ip)


def merge_indicators(lists: Iterable[Iterable[Indicator]]) -> List[Indicator]:
    """Combine feeds. The same indicator in several feeds is kept once, with every campaign named
    and the stronger tier (confirmed beats lead)."""
    merged: Dict[Tuple[str, str], Indicator] = {}
    for items in lists:
        for ind in items:
            key = (ind.kind, ind.value)
            current = merged.get(key)
            if current is None:
                merged[key] = ind
                continue
            tier = "confirmed" if "confirmed" in (current.tier, ind.tier) else current.tier
            names = [n for n in current.campaign.split("; ") + ind.campaign.split("; ") if n]
            campaign = "; ".join(dict.fromkeys(names))
            source = current.source if ind.source in current.source else f"{current.source}; {ind.source}"
            merged[key] = replace(current, tier=tier, campaign=campaign, source=source)
    return list(merged.values())
