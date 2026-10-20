"""Ports listening for incoming connections, matched to the process name that owns each one.

No port is flagged just for being open. There's no verified "bad ports" list, so that would
be guessing. It only ties a published file-name indicator to one more observable: a program
with a campaign's name is listening. Every listener still goes into the inventory for
baseline.py, matched or not.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Callable, List, NamedTuple, Optional

from .checks_network import capture_text
from .evidence import CheckResult, make_finding
from .ioc import IndicatorSet

_WIN_LISTEN = re.compile(r"^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)\s*$", re.IGNORECASE)
_SS_LISTEN = re.compile(r"^\s*(?:tcp|LISTEN)\S*\s+\S+\s+\S+\s+(\S+):(\d+)\s+\S+.*?(?:pid=(\d+))?", re.IGNORECASE)
_LSOF_LISTEN = re.compile(r"^(\S+)\s+(\d+)\s+.*?(?:\*|[\d.:a-fA-F]+):(\d+)\s*\(LISTEN\)\s*$")


class Listener(NamedTuple):
    address: str
    port: str
    pid: Optional[str]
    process: Optional[str]


def parse_windows_listeners(text: str, pid_names: Optional[dict] = None) -> List[Listener]:
    out = []
    for line in text.splitlines():
        match = _WIN_LISTEN.match(line)
        if match:
            address, port, pid = match.groups()
            name = (pid_names or {}).get(pid)
            out.append(Listener(address, port, pid, name))
    return out


def parse_ss_listeners(text: str) -> List[Listener]:
    out = []
    for line in text.splitlines():
        if "LISTEN" not in line.upper():
            continue
        match = _SS_LISTEN.search(line)
        if not match:
            continue
        address, port, _ = match.groups()
        pid_match = re.search(r"pid=(\d+)", line)
        name_match = re.search(r'"([^"]+)"', line)
        out.append(Listener(address, port, pid_match.group(1) if pid_match else None,
                             name_match.group(1) if name_match else None))
    return out


def parse_lsof_listeners(text: str) -> List[Listener]:
    out = []
    for line in text.splitlines()[1:]:  # skip header
        match = _LSOF_LISTEN.match(line.strip())
        if not match:
            continue
        process, pid, port = match.groups()
        out.append(Listener("*", port, pid, process))
    return out


def check_ports(
    indicators: IndicatorSet,
    platform: Optional[str] = None,
    run: Callable = subprocess.run,
) -> CheckResult:
    result = CheckResult("ports")
    platform = platform or sys.platform
    names = indicators.by_kind("filename")
    errors: List[str] = []

    listeners: List[Listener] = []
    if platform == "win32":
        cap = capture_text(run, ["netstat", "-ano", "-p", "TCP"])
        if cap.stdout is not None:
            listeners = parse_windows_listeners(cap.stdout)
        elif cap.error:
            errors.append(f"netstat: {cap.error}")
    elif platform.startswith("linux"):
        cap = capture_text(run, ["ss", "-tlnp"])
        if cap.stdout is not None:
            listeners = parse_ss_listeners(cap.stdout)
        elif cap.error:
            errors.append(f"ss: {cap.error}")
    else:  # darwin and other POSIX
        cap = capture_text(run, ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
        if cap.stdout is not None:
            listeners = parse_lsof_listeners(cap.stdout)
        elif cap.error:
            errors.append(f"lsof: {cap.error}")

    if not listeners and errors:
        result.status = "error"
        result.note = f"could not list listening ports ({'; '.join(errors)})"
        return result

    result.examined = len(listeners)
    unnamed = 0
    for listener in listeners:
        detail = f"{listener.address}:{listener.port}" + (f" ({listener.process})" if listener.process else "")
        result.inventory.append((f"PID {listener.pid or '?'}", detail))
        if not listener.process:
            unnamed += 1
            continue
        ind = names.get(Path(listener.process).name.lower())
        if ind is not None:
            result.findings.append(
                make_finding("ports", "listener-lead", ind, f"{listener.address}:{listener.port}",
                             f"listening process {listener.process!r} matches a campaign name")
            )
    if unnamed:
        result.gaps.append(f"{unnamed} listener(s) could not be matched to an owning process name")
    if not listeners:
        result.gaps.append("no listening TCP ports were found, or the output was not recognised")
    return result
