"""Programs registered to start automatically.

Each source yields (location, command). The executable's base name is matched
against filename indicators. Full paths are not compared, so a renamed or moved
copy with the same name is still reported.
"""
from __future__ import annotations

import os
import plistlib
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from .evidence import CheckResult, make_finding
from .ioc import IndicatorSet

Entry = Tuple[str, str]
ValueReader = Callable[[str], Sequence[Tuple[str, str]]]
_MAX_DETAIL = 200
WINDOWS_RUN_KEYS = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
)


def command_basename(command: str) -> Optional[str]:
    command = command.strip()
    if not command:
        return None
    if command.startswith('"'):
        end = command.find('"', 1)
        token = command[1:end] if end > 0 else command[1:]
    else:
        token = command.split()[0]
    name = re.split(r"[\\/]", token)[-1].strip().lower()
    return name or None


def _winreg_values(subkey: str) -> List[Tuple[str, str]]:
    """Return (name, data) string values under HKCU\\<subkey>. Windows only."""
    import winreg

    values: List[Tuple[str, str]] = []
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey)
    except OSError:
        return values
    with key:
        index = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(key, index)
            except OSError:
                break
            index += 1
            if isinstance(data, str):
                values.append((name, data))
    return values


def windows_run_entries(reader: Optional[ValueReader] = None) -> List[Entry]:
    read = reader or _winreg_values
    entries: List[Entry] = []
    for subkey in WINDOWS_RUN_KEYS:
        for name, data in read(subkey):
            entries.append((f"HKCU\\{subkey}\\{name}", data))
    return entries


_TOKEN = re.compile(r'"([^"]*)"|(\S+)')
_MAX_TOKENS = 24


def command_names(command: str) -> List[str]:
    """Base names worth matching in a command line.

    The program itself always counts. Later arguments count only when they look like a file
    (they contain a dot), so ``cmd /c payload.exe`` is caught but ``-q`` and ``*/5`` are not.
    """
    names: List[str] = []
    for index, match in enumerate(_TOKEN.finditer(command.strip())):
        if index >= _MAX_TOKENS:
            break
        token = (match.group(1) if match.group(1) is not None else match.group(2)).strip()
        name = re.split(r"[\\/]", token)[-1].strip().lower().rstrip(";,)")
        if not name or name.isdigit():
            continue
        if index == 0 or "." in name:
            names.append(name)
    return names


def _hklm_values(subkey: str) -> List[Tuple[str, str]]:  # pragma: no cover - Windows only
    import winreg

    values: List[Tuple[str, str]] = []
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey)
    except OSError:
        return values
    with key:
        index = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(key, index)
            except OSError:
                break
            index += 1
            if isinstance(data, str):
                values.append((name, data))
    return values


def _service_images() -> List[Tuple[str, str]]:  # pragma: no cover - Windows only
    import winreg

    out: List[Tuple[str, str]] = []
    base = r"SYSTEM\CurrentControlSet\Services"
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
    except OSError:
        return out
    with root:
        index = 0
        while True:
            try:
                name = winreg.EnumKey(root, index)
            except OSError:
                break
            index += 1
            try:
                with winreg.OpenKey(root, name) as svc:
                    image, _ = winreg.QueryValueEx(svc, "ImagePath")
            except OSError:
                continue
            if isinstance(image, str):
                out.append((name, image))
    return out


def scheduled_task_entries(tasks_dir: Path) -> Tuple[List[Entry], List[str]]:
    """Read the task definition XML files Windows keeps under System32\\Tasks."""
    entries: List[Entry] = []
    problems: List[str] = []
    unreadable = 0
    if not tasks_dir.is_dir():
        return entries, ["the scheduled-task folder was not found"]
    for dirpath, _dirs, files in os.walk(tasks_dir):
        for name in files:
            path = Path(dirpath) / name
            try:
                raw = path.read_bytes()
                if len(raw) > 2_000_000:
                    raise ValueError("too large")
                lowered = raw.lower().replace(b"\x00", b"")
                if b"<!doctype" in lowered or b"<!entity" in lowered:
                    raise ValueError("DTD not accepted")
                root = ET.fromstring(raw)
            except (OSError, ValueError, ET.ParseError):
                unreadable += 1
                continue
            command_parts: List[str] = []
            for element in root.iter():
                tag = element.tag.rsplit("}", 1)[-1]
                if tag == "Command" and element.text:
                    command_parts.append(element.text.strip())
                elif tag == "Arguments" and element.text and command_parts:
                    command_parts[-1] += " " + element.text.strip()
            for command in command_parts:
                entries.append((f"Task {path.relative_to(tasks_dir)}", command))
    if unreadable:
        problems.append(
            f"{unreadable} scheduled-task definitions could not be read (often need administrator rights)"
        )
    return entries, problems


def startup_folder_names(dirs: Iterable[Path]) -> Tuple[List[Path], List[str]]:
    files: List[Path] = []
    problems: List[str] = []
    for directory in dirs:
        if not directory.is_dir():
            continue
        try:
            files.extend(p for p in sorted(directory.iterdir()) if p.is_file())
        except OSError as exc:
            problems.append(f"cannot list {directory} ({exc.__class__.__name__})")
    return files, problems


def cron_lines() -> Tuple[List[Tuple[str, str]], List[str]]:
    """Return (location, line) for the user's crontab and the system cron files."""
    lines: List[Tuple[str, str]] = []
    problems: List[str] = []
    try:
        proc = subprocess.run(["crontab", "-l"], capture_output=True, timeout=10)
        if proc.returncode == 0:
            for line in proc.stdout.decode("utf-8", "replace").splitlines():
                lines.append(("user crontab", line))
    except (OSError, subprocess.SubprocessError):
        problems.append("the user crontab could not be listed")
    sources = [Path("/etc/crontab")]
    cron_d = Path("/etc/cron.d")
    if cron_d.is_dir():
        try:
            sources.extend(sorted(p for p in cron_d.iterdir() if p.is_file()))
        except OSError:
            problems.append("/etc/cron.d could not be listed")
    for source in sources:
        for line in _read_lines(source):
            lines.append((str(source), line))
    return lines, problems


def cron_entries(lines: Iterable[Tuple[str, str]]) -> List[Entry]:
    entries: List[Entry] = []
    for location, line in lines:
        text = line.strip()
        if not text or text.startswith("#") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", text):
            continue
        entries.append((location, text))
    return entries


def launchd_entries(dirs: Iterable[Path]) -> Tuple[List[Entry], List[str]]:
    entries: List[Entry] = []
    problems: List[str] = []
    for directory in dirs:
        if not directory.is_dir():
            continue
        try:
            plists = sorted(directory.glob("*.plist"))
        except OSError as exc:
            problems.append(f"cannot list {directory} ({exc.__class__.__name__})")
            continue
        for plist in plists:
            try:
                with plist.open("rb") as fh:
                    data = plistlib.load(fh)
            except Exception:  # any malformed plist is reported, never fatal
                problems.append(f"unreadable launchd plist {plist}")
                continue
            if not isinstance(data, dict):
                continue
            args = data.get("ProgramArguments")
            if isinstance(args, list) and args and isinstance(args[0], str):
                entries.append((str(plist), args[0]))
            elif isinstance(data.get("Program"), str):
                entries.append((str(plist), data["Program"]))
    return entries, problems


def login_items_names(home: Path) -> Tuple[List[str], List[str]]:
    """Reads the older login-items plist. macOS 13+'s BackgroundItems-v*.btm is a binary
    plist and isn't parsed here; see the gap it reports instead."""
    names: List[str] = []
    problems: List[str] = []
    plist = home / "Library" / "Preferences" / "com.apple.loginitems.plist"
    if plist.is_file():
        try:
            with plist.open("rb") as fh:
                data = plistlib.load(fh)
        except Exception:
            problems.append(f"unreadable login items plist {plist}")
        else:
            for item in data.get("SessionItems", {}).get("CustomListItems", []) if isinstance(data, dict) else []:
                if isinstance(item, dict) and isinstance(item.get("Name"), str):
                    names.append(item["Name"])
    bg_dir = home / "Library" / "Application Support" / "com.apple.backgroundtaskmanagementagent"
    if bg_dir.is_dir():
        problems.append(
            f"background task items in {bg_dir} are stored as binary plists and are not parsed in this version"
        )
    return names, problems


def _read_lines(path: Path) -> List[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def desktop_entries(dirs: Iterable[Path]) -> List[Entry]:
    entries: List[Entry] = []
    for directory in dirs:
        if not directory.is_dir():
            continue
        for desktop in sorted(directory.glob("*.desktop")):
            for line in _read_lines(desktop):
                if line.startswith("Exec="):
                    entries.append((str(desktop), line[len("Exec="):]))
                    break
    return entries


def systemd_entries(dirs: Iterable[Path]) -> List[Entry]:
    entries: List[Entry] = []
    for directory in dirs:
        if not directory.is_dir():
            continue
        for unit in sorted(directory.glob("*.service")):
            for line in _read_lines(unit):
                if line.startswith("ExecStart="):
                    command = line[len("ExecStart="):].lstrip("-@!+:")
                    entries.append((str(unit), command))
                    break
    return entries


def check_persistence(
    indicators: IndicatorSet,
    home: Optional[Path] = None,
    platform: Optional[str] = None,
    win_reader: Optional[ValueReader] = None,
    hklm_reader: Optional[ValueReader] = None,
    services_reader: Optional[Callable[[], Sequence[Tuple[str, str]]]] = None,
    tasks_dir: Optional[Path] = None,
    startup_dirs: Optional[Sequence[Path]] = None,
    cron_reader: Optional[Callable[[], Tuple[List[Tuple[str, str]], List[str]]]] = None,
) -> CheckResult:
    result = CheckResult("persistence")
    real_windows = sys.platform == "win32"
    platform = platform or sys.platform
    home = Path(home) if home else Path.home()
    names = indicators.by_kind("filename")
    entries: List[Entry] = []
    shortcut_files: List[Path] = []

    if platform == "win32":
        entries.extend(windows_run_entries(win_reader))
        read_machine = hklm_reader or (_hklm_values if real_windows else None)
        if read_machine is not None:
            for subkey in WINDOWS_RUN_KEYS:
                for name, data in read_machine(subkey):
                    entries.append((f"HKLM\\{subkey}\\{name}", data))
        read_services = services_reader or (_service_images if real_windows else None)
        if read_services is not None:
            entries.extend((f"Service {name}", image) for name, image in read_services())
        folder = tasks_dir if tasks_dir is not None else Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
        found, problems = scheduled_task_entries(folder)
        entries.extend(found)
        result.gaps.extend(problems)
        if startup_dirs is None:
            startup_dirs = []
            appdata, programdata = os.environ.get("APPDATA"), os.environ.get("PROGRAMDATA")
            if appdata:
                startup_dirs.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
            if programdata:
                startup_dirs.append(Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp")
        shortcut_files, problems = startup_folder_names(startup_dirs)
        result.gaps.extend(problems)
        result.gaps.append("WMI event subscriptions and COM registrations are not checked in this version")
    elif platform == "darwin":
        found, problems = launchd_entries([
            home / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ])
        entries.extend(found)
        result.gaps.extend(problems)
        cron, cron_problems = (cron_reader or cron_lines)()
        entries.extend(cron_entries(cron))
        result.gaps.extend(cron_problems)
        login_names, login_problems = login_items_names(home)
        result.gaps.extend(login_problems)
        for login_name in login_names:
            result.examined += 1
            ind = names.get(login_name.strip().lower())
            if ind is not None:
                result.findings.append(
                    make_finding("persistence", "autostart", ind, "login items",
                                 f'login item "{login_name}" matches a campaign name')
                )
    else:
        entries.extend(desktop_entries([home / ".config" / "autostart"]))
        entries.extend(systemd_entries([home / ".config" / "systemd" / "user", Path("/etc/systemd/system")]))
        cron, cron_problems = (cron_reader or cron_lines)()
        entries.extend(cron_entries(cron))
        result.gaps.extend(cron_problems)

    result.examined = len(entries) + len(shortcut_files)
    result.inventory.extend((location, command.strip()[:_MAX_DETAIL]) for location, command in entries)
    result.inventory.extend((str(path), "startup folder item") for path in shortcut_files)
    for location, command in entries:
        for name in command_names(command):
            ind = names.get(name)
            if ind is not None:
                shown = command.strip()[:_MAX_DETAIL]
                result.findings.append(make_finding("persistence", "autostart", ind, location, f"starts: {shown}"))
                break

    for path in shortcut_files:
        ind = names.get(path.name.lower())
        if ind is None and path.suffix.lower() == ".lnk":
            try:
                blob = path.read_bytes()[:65536]
            except OSError:
                continue
            text = blob.decode("latin-1").lower() + blob.decode("utf-16-le", "ignore").lower()
            for wanted, candidate in names.items():
                if wanted in text:
                    ind = candidate
                    break
        if ind is not None:
            result.findings.append(
                make_finding("persistence", "autostart", ind, str(path), "item in a Startup folder refers to an indicator name")
            )
    return result
