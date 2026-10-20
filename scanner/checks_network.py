"""Hosts file and the Windows DNS resolver cache.

The hosts file is read directly. The resolver cache is read with the local
`ipconfig /displaydns` command, which does not touch the network.
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterator, List, Optional, Tuple

from .evidence import CheckResult, make_finding
from .ioc import IndicatorSet, normalize_host

SINK_ADDRESSES = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1"})


def hosts_path(platform: Optional[str] = None) -> Path:
    platform = platform or sys.platform
    if platform == "win32":
        root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
        return root / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def parse_hosts(text: str) -> Iterator[Tuple[str, str]]:
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        address = parts[0]
        for name in parts[1:]:
            yield address, normalize_host(name)


def check_hosts(indicators: IndicatorSet, path: Optional[Path] = None) -> CheckResult:
    result = CheckResult("hosts")
    target = Path(path) if path else hosts_path()
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result.status = "error"
        result.note = f"cannot read {target}: {exc.__class__.__name__}"
        return result

    for address, name in parse_hosts(text):
        result.examined += 1
        ind = indicators.find_host(name)
        if ind is not None:
            grade = "hosts-sink" if address in SINK_ADDRESSES else "hosts-config"
            result.findings.append(
                make_finding("hosts", grade, ind, f"{target} ({name})", f"maps to {address}")
            )
        ip_ind = indicators.find_endpoint(address)
        if ip_ind is not None and ip_ind.kind == "ip":
            result.findings.append(
                make_finding("hosts", "hosts-config", ip_ind, f"{target} ({name})", f"{name} is mapped to indicator IP {address}")
            )
    return result


def decode_console(data: bytes) -> str:
    """Console tools write in the OEM code page (e.g. cp437/cp850), not UTF-8."""
    for encoding in ("utf-8", "cp850", "cp437"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


# Fixed commands, no user input. ipconfig is the fallback when Get-DnsClientCache fails.
POWERSHELL_CMD = [
    "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
    "Get-DnsClientCache -ErrorAction Stop | Select-Object Entry,Data "
    "| ConvertTo-Json -Compress -AsArray",
]
IPCONFIG_CMD = ["ipconfig", "/displaydns"]

_BLOCK_SPLIT = re.compile(r"^\s*-{5,}\s*$", re.MULTILINE)
# "    <label> . . . . : <value>" in any language: the dotted leader is the stable part.
_LEADER_LINE = re.compile(r"^\s+.*?(?:\s\.)+\s*:\s*(\S+)\s*$")
_NAME_LINE = re.compile(r"^[A-Za-z0-9_*][A-Za-z0-9_.*-]*$")


def names_from_ipconfig(text: str) -> List[str]:
    """First dotted-leader line of each record block is the record name, whatever the language."""
    names: List[str] = []
    for block in _BLOCK_SPLIT.split(text):
        for line in block.splitlines():
            match = _LEADER_LINE.match(line)
            if match:
                names.append(match.group(1))
                break
    return names


def endpoints_from_ipconfig(text: str) -> List[str]:
    """Record names plus any IPv4 answers in the dotted-leader lines, in any language."""
    out = list(names_from_ipconfig(text))
    for line in text.splitlines():
        match = _LEADER_LINE.match(line)
        if match:
            value = match.group(1)
            try:
                ipaddress.IPv4Address(value)
            except ValueError:
                continue
            out.append(value)
    return out


def names_from_powershell(text: str) -> List[str]:
    """Parse the ConvertTo-Json output of Select-Object Entry,Data.

    A single matching record comes back as one JSON object rather than a list even with
    -AsArray on older PowerShell, so both shapes are accepted. Anything that fails to parse
    falls back to the old line-based reading, in case a future PowerShell changes the format.
    """
    import json

    out: List[str] = []
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if data is not None:
        rows = data if isinstance(data, list) else [data]
        for row in rows:
            if not isinstance(row, dict):
                continue
            for key in ("Entry", "Data"):
                value = row.get(key)
                if isinstance(value, str) and value:
                    out.append(value)
        return out
    for line in text.splitlines():
        line = line.strip()
        if "." in line and _NAME_LINE.match(line):
            out.append(line)
    return out


def _capture(run: Callable, command: List[str]) -> "CaptureResult":
    """Run a command; return its decoded stdout, its exit status and a short stderr excerpt."""
    try:
        proc = run(command, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return CaptureResult(None, None, f"{exc.__class__.__name__}: {exc}")
    code = getattr(proc, "returncode", 0)
    err = getattr(proc, "stderr", b"") or b""
    if isinstance(err, str):
        err = err.encode("utf-8")
    err_text = decode_console(err).strip()
    if code not in (0, None):
        return CaptureResult(None, code, err_text[:300] or f"exit code {code}")
    out = proc.stdout
    if isinstance(out, str):
        out = out.encode("utf-8")
    return CaptureResult(decode_console(out or b""), code, err_text[:300] if err_text else None)


class CaptureResult:
    def __init__(self, stdout: Optional[str], code: Optional[int], error: Optional[str]):
        self.stdout = stdout
        self.code = code
        self.error = error


capture_text = _capture  # public name used by the connections check


def check_dns_cache(
    indicators: IndicatorSet,
    platform: Optional[str] = None,
    run: Callable = subprocess.run,
) -> CheckResult:
    result = CheckResult("dns-cache")
    if (platform or sys.platform) != "win32":
        result.status = "skipped"
        result.note = "the resolver cache is read only on Windows in this version"
        return result

    names: List[str] = []
    ran_any = False
    diagnostics: List[str] = []

    ps = _capture(run, POWERSHELL_CMD)
    if ps.stdout is not None:
        ran_any = True
        names = names_from_powershell(ps.stdout)
    elif ps.error:
        diagnostics.append(f"Get-DnsClientCache: {ps.error}")

    if not names:
        ip = _capture(run, IPCONFIG_CMD)
        if ip.stdout is not None:
            ran_any = True
            names = endpoints_from_ipconfig(ip.stdout)
        elif ip.error:
            diagnostics.append(f"ipconfig: {ip.error}")

    if not ran_any:
        result.status = "error"
        detail = "; ".join(diagnostics) if diagnostics else "both commands failed"
        result.note = f"could not read the DNS cache ({detail})"
        return result
    if not names:
        detail = f" ({'; '.join(diagnostics)})" if diagnostics else ""
        result.gaps.append(
            f"no DNS cache records were read; the cache may genuinely be empty{detail}"
        )

    seen = set()
    for raw in names:
        name = normalize_host(raw)
        if name in seen:
            continue
        seen.add(name)
        result.examined += 1
        ind = indicators.find_endpoint(name)
        if ind is not None:
            result.findings.append(
                make_finding("dns-cache", "dns-cache", ind, "Windows DNS resolver cache", f"cached record {name}")
            )
    result.gaps.append("DNS-Client logging is not checked, so older lookups cannot be seen from the cache")
    return result
