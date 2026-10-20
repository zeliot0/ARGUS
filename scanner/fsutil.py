"""Copying files that another program may still have open.

A plain copy of a locked browser database fails with PermissionError on Windows; the
fallback opens it with full sharing instead. The source is only ever opened for reading.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Callable, Optional

_GENERIC_READ = 0x80000000
_SHARE_ALL = 0x1 | 0x2 | 0x4
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80


def _copy_shared_windows(src: Path, dest: Path) -> None:  # pragma: no cover - Windows only
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    ]
    handle = kernel32.CreateFileW(
        str(src), _GENERIC_READ, _SHARE_ALL, None, _OPEN_EXISTING, _FILE_ATTRIBUTE_NORMAL, None
    )
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    fd = msvcrt.open_osfhandle(handle, os.O_RDONLY)
    with os.fdopen(fd, "rb") as source, open(dest, "wb") as target:
        shutil.copyfileobj(source, target)


def copy_file(
    src: Path,
    dest: Path,
    platform: Optional[str] = None,
    shared_copy: Optional[Callable[[Path, Path], None]] = None,
) -> None:
    """Copy src to dest; on Windows fall back to a fully shared read if the file is locked."""
    try:
        shutil.copy2(src, dest)
        return
    except (PermissionError, OSError):
        if (platform or sys.platform) != "win32":
            raise
    (shared_copy or _copy_shared_windows)(Path(src), Path(dest))
