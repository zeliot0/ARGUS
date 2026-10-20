"""Windows-only: WMI permanent event subscriptions and per-user COM class overrides.

Both are used as fileless persistence. WMI consumers are read through PowerShell; COM
overrides are read straight from the registry, since HKCU\\Software\\Classes is checked
before HKLM, so a CLSID placed there overrides the real one with no admin rights needed.
"""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Callable, List, Optional, Sequence, Tuple

from .checks_persistence import command_names
from .evidence import CheckResult, make_finding
from .ioc import IndicatorSet

ClsidReader = Callable[[], Sequence[Tuple[str, str]]]  # (CLSID path, InprocServer32 default value)

WMI_CMD = [
    "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
    "Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer "
    "-ErrorAction SilentlyContinue | Select-Object Name,CommandLineTemplate | ConvertTo-Json -Compress -AsArray; "
    "Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer "
    "-ErrorAction SilentlyContinue | Select-Object Name,ScriptFileName | ConvertTo-Json -Compress -AsArray",
]


def parse_wmi_consumers(text: str) -> List[Tuple[str, str]]:
    """(consumer name, command or script path) pairs from the two ConvertTo-Json blocks."""
    out: List[Tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line in ("[]", "null"):
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        rows = data if isinstance(data, list) else [data]
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = str(row.get("Name", ""))
            command = row.get("CommandLineTemplate") or row.get("ScriptFileName")
            if isinstance(command, str) and command:
                out.append((name, command))
    return out


def _registry_clsid_overrides() -> List[Tuple[str, str]]:  # pragma: no cover - Windows only
    import winreg

    out: List[Tuple[str, str]] = []
    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\CLSID")
    except OSError:
        return out
    with root:
        index = 0
        while True:
            try:
                clsid = winreg.EnumKey(root, index)
            except OSError:
                break
            index += 1
            try:
                with winreg.OpenKey(root, clsid + r"\InprocServer32") as sub:
                    value, _ = winreg.QueryValueEx(sub, None)
            except OSError:
                continue
            if isinstance(value, str) and value:
                out.append((f"HKCU\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32", value))
    return out


def check_wmi(
    indicators: IndicatorSet,
    platform: Optional[str] = None,
    run: Callable = subprocess.run,
    clsid_reader: Optional[ClsidReader] = None,
) -> CheckResult:
    result = CheckResult("wmi")
    if (platform or sys.platform) != "win32":
        result.status = "skipped"
        result.note = "WMI event subscriptions and per-user COM overrides are Windows-only"
        return result

    names = indicators.by_kind("filename")

    try:
        proc = run(WMI_CMD, capture_output=True, timeout=30)
        out = proc.stdout
        if isinstance(out, bytes):
            out = out.decode("utf-8", errors="replace")
        consumers = parse_wmi_consumers(out or "")
    except (OSError, subprocess.SubprocessError) as exc:
        result.gaps.append(f"WMI event subscriptions could not be read ({exc.__class__.__name__})")
        consumers = []

    for consumer_name, command in consumers:
        result.examined += 1
        result.inventory.append((f"WMI consumer {consumer_name}", command.strip()[:200]))
        for base in command_names(command):
            ind = names.get(base)
            if ind is not None:
                result.findings.append(
                    make_finding("wmi", "wmi-consumer", ind, f"WMI consumer {consumer_name}",
                                 f"runs: {command.strip()[:200]}")
                )
                break

    read = clsid_reader if clsid_reader is not None else (_registry_clsid_overrides if sys.platform == "win32" else None)
    overrides = read() if read is not None else []
    if read is None and clsid_reader is None:
        result.gaps.append("per-user COM class overrides could not be read on this platform")
    for location, server in overrides:
        result.examined += 1
        result.inventory.append((location, server))
        for base in command_names(server):
            ind = names.get(base)
            if ind is not None:
                result.findings.append(make_finding("wmi", "com-hijack", ind, location, f"InprocServer32 = {server}"))
                break
    return result
