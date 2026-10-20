"""Processes running right now, matched against file name and SHA-256 indicators.

No process memory is touched. A process's on-disk executable is hashed the same way the
files check hashes anything else. A process whose path we can't read is still matched on
its reported name, which is weak evidence on its own.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, List, NamedTuple, Optional

from .checks_files import MAX_HASH_BYTES, sha256_file
from .evidence import CheckResult, make_finding
from .ioc import IndicatorSet

PS_PROCESS_CMD = [
    "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
    "Get-Process | Select-Object Id,ProcessName,Path | ConvertTo-Json -Compress -AsArray",
]


class Proc(NamedTuple):
    pid: str
    name: str
    path: Optional[str]


def processes_from_proc_fs(proc_dir: Path) -> List[Proc]:
    """Linux: /proc/<pid>/exe and /proc/<pid>/comm, read directly with no subprocess."""
    out: List[Proc] = []
    try:
        pids = sorted(p.name for p in proc_dir.iterdir() if p.name.isdigit())
    except OSError:
        return out
    for pid in pids:
        entry = proc_dir / pid
        path: Optional[str] = None
        try:
            path = os.readlink(entry / "exe")
        except OSError:
            pass
        name = ""
        try:
            name = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            pass
        if not name and path:
            name = Path(path).name
        if name:
            out.append(Proc(pid, name, path))
    return out


def _parse_windows_json(text: str) -> List[Proc]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    rows = data if isinstance(data, list) else [data]
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = str(row.get("ProcessName", ""))
        path = row.get("Path")
        out.append(Proc(str(row.get("Id", "")), name, path if isinstance(path, str) and path else None))
    return out


def _parse_ps_axo(text: str) -> List[Proc]:
    """macOS / generic Unix fallback: 'ps -axo pid=,comm=' (full path in comm on macOS)."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        pid, command = parts
        path = command if command.startswith("/") else None
        out.append(Proc(pid, Path(command).name, path))
    return out


def list_processes(
    platform: Optional[str] = None,
    run: Callable = subprocess.run,
    proc_dir: Optional[Path] = None,
) -> "tuple[List[Proc], List[str]]":
    """(processes, problems). Problems are reasons some or all processes could not be listed."""
    platform = platform or sys.platform
    problems: List[str] = []

    if platform == "win32":
        try:
            proc = run(PS_PROCESS_CMD, capture_output=True, timeout=30)
            out = proc.stdout
            if isinstance(out, bytes):
                out = out.decode("utf-8", errors="replace")
            procs = _parse_windows_json(out or "")
            if not procs and (out or "").strip() not in ("", "[]"):
                problems.append("Get-Process output was not recognised")
            return procs, problems
        except (OSError, subprocess.SubprocessError) as exc:
            return [], [f"could not list processes ({exc.__class__.__name__})"]

    if platform.startswith("linux"):
        root = proc_dir if proc_dir is not None else Path("/proc")
        procs = processes_from_proc_fs(root)
        if not procs:
            problems.append(f"no process entries were found under {root}")
        return procs, problems

    # darwin and anything else with a POSIX ps
    try:
        proc = run(["ps", "-axo", "pid=,comm="], capture_output=True, timeout=30)
        out = proc.stdout
        if isinstance(out, bytes):
            out = out.decode("utf-8", errors="replace")
        procs = _parse_ps_axo(out or "")
        if not procs:
            problems.append("'ps' output was not recognised")
        return procs, problems
    except (OSError, subprocess.SubprocessError) as exc:
        return [], [f"could not list processes ({exc.__class__.__name__})"]


def check_processes(
    indicators: IndicatorSet,
    platform: Optional[str] = None,
    run: Callable = subprocess.run,
    proc_dir: Optional[Path] = None,
    quick: bool = False,
    max_hash_bytes: int = MAX_HASH_BYTES,
) -> CheckResult:
    result = CheckResult("processes")
    procs, problems = list_processes(platform, run, proc_dir)
    result.gaps.extend(problems)
    if not procs:
        if not problems:
            result.gaps.append("no running processes could be listed")
        return result

    names = indicators.by_kind("filename")
    hashes = indicators.by_kind("sha256")
    hashing = bool(hashes) and not quick
    if hashes and quick:
        result.gaps.append("SHA-256 comparison of process executables skipped (--quick)")

    result.examined = len(procs)
    no_path = 0
    unreadable: List[str] = []
    seen_hash_hits = set()
    for p in procs:
        matched_by_hash = False
        if hashing and p.path:
            try:
                path = Path(p.path)
                if path.is_file() and path.stat().st_size <= max_hash_bytes:
                    digest = sha256_file(path)
                    ind = hashes.get(digest)
                    if ind is not None:
                        key = (p.pid, digest)
                        if key not in seen_hash_hits:
                            seen_hash_hits.add(key)
                            result.findings.append(
                                make_finding("processes", "process-match", ind, f"PID {p.pid} ({p.path})",
                                             f"SHA-256 {digest}")
                            )
                        matched_by_hash = True
            except OSError:
                unreadable.append(f"PID {p.pid} ({p.path})")

        base = Path(p.path).name.lower() if p.path else p.name.lower()
        if not matched_by_hash and base:
            ind = names.get(base)
            if ind is not None:
                result.findings.append(
                    make_finding("processes", "process-name-lead", ind, f"PID {p.pid}",
                                 f"process name {base!r} matches a campaign name")
                )
        if not p.path:
            no_path += 1

    if no_path:
        result.gaps.append(f"{no_path} process(es) had no accessible executable path; only the name was checked")
    if unreadable:
        sample = "; ".join(unreadable[:5])
        more = len(unreadable) - 5
        result.gaps.append(f"{len(unreadable)} process executable(s) could not be read: {sample}" + (f" (and {more} more)" if more > 0 else ""))
    return result
