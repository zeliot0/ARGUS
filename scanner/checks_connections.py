"""Open network connections right now, compared with IP indicators.

Reads `netstat -n` (or `ss -tn` on Linux): lists what's already open, doesn't create any.
IPv4 addresses are pulled out by pattern, so localised column headers don't matter. A
connection that already ended can't be seen.
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from typing import Callable, List, Optional

from .checks_network import capture_text
from .evidence import CheckResult, make_finding
from .ioc import IndicatorSet

_IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")


def parse_connection_ips(text: str) -> List[str]:
    seen = []
    found = set()
    for match in _IPV4.finditer(text):
        try:
            ip = str(ipaddress.IPv4Address(match.group(1)))
        except ValueError:
            continue
        if ip not in found:
            found.add(ip)
            seen.append(ip)
    return seen


def check_connections(
    indicators: IndicatorSet,
    platform: Optional[str] = None,
    run: Callable = subprocess.run,
) -> CheckResult:
    result = CheckResult("connections")
    platform = platform or sys.platform
    commands = [["netstat", "-n"]]
    if platform.startswith("linux"):
        commands.insert(0, ["ss", "-tn"])

    text: Optional[str] = None
    errors: List[str] = []
    for command in commands:
        cap = capture_text(run, command)
        if cap.stdout is not None:
            text = cap.stdout
            break
        if cap.error:
            errors.append(f"{command[0]}: {cap.error}")
    if text is None:
        result.status = "error"
        detail = f" ({'; '.join(errors)})" if errors else ""
        result.note = f"could not list connections (netstat/ss not available or failed){detail}"
        return result

    ips = parse_connection_ips(text)
    result.examined = len(ips)
    for ip in ips:
        ind = indicators.get("ip", ip)
        if ind is not None:
            result.findings.append(
                make_finding("connections", "connection", ind, "open network connection", f"connection involving {ip}")
            )
    if not ips:
        result.gaps.append("no IPv4 connections were listed; there may be none open, or the output was not recognised")
    result.gaps.append("only connections open at this moment and IPv4 addresses are checked")
    return result
