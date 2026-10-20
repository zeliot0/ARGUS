"""File name and SHA-256 checks in user-writable locations.

Each folder gets its own budget so one huge folder can't starve the rest. Every limit
hit, and every file that can't be read, shows up as a named gap.
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path
from typing import Callable, Iterator, List, Optional

from .evidence import CheckResult, make_finding
from .ioc import IndicatorSet

MAX_FILES = 20000  # per folder
MAX_DEPTH = 4
MAX_HASH_BYTES = 50 * 1024 * 1024
_CHUNK = 1 << 20
_SAMPLE_UNREADABLE = 5


# Cache/dependency folders: skipped by default so the per-folder budget goes further.
SKIP_DIR_NAMES = frozenset({
    "cache", "caches", "code cache", "gpucache", "cache_data", "cachestorage", "service worker",
    "shadercache", "grshadercache", "dawncache", "dawngraphitecache", "dawnwebgpucache",
    "component_crx_cache", "crashpad", "node_modules", "__pycache__", ".git", "site-packages",
    "pip", ".gradle", ".npm", "blob_storage", "indexeddb", "local storage", "session storage",
})


def candidate_roots(home: Optional[Path] = None, platform: Optional[str] = None) -> List[Path]:
    home = Path(home) if home else Path.home()
    platform = platform or sys.platform
    roots = [home / "Downloads", home / "Desktop", home / "Documents", Path(tempfile.gettempdir())]
    if platform == "win32":
        for var in ("APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PUBLIC"):
            if os.environ.get(var):
                roots.append(Path(os.environ[var]))
    else:
        roots.extend([home / ".local" / "bin", Path("/var/tmp"), Path("/dev/shm")])
    seen = set()
    unique: List[Path] = []
    for root in roots:
        try:
            key = str(root.resolve())
        except OSError:
            continue
        if key not in seen and root.is_dir():
            seen.add(key)
            unique.append(root)
    return unique


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _walk(root: Path, max_depth: int, skipped: Optional[List[str]] = None) -> Iterator[Path]:
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        depth = len(Path(dirpath).parts) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
        elif skipped is not None:
            keep = []
            for d in sorted(dirnames):
                if d.lower() in SKIP_DIR_NAMES:
                    skipped.append(os.path.join(dirpath, d))
                else:
                    keep.append(d)
            dirnames[:] = keep
        for name in filenames:
            yield Path(dirpath) / name


def check_files(
    indicators: IndicatorSet,
    roots: Optional[List[Path]] = None,
    quick: bool = False,
    max_files: int = MAX_FILES,
    tick: Optional[Callable[[int], None]] = None,
    skip_caches: bool = True,
) -> CheckResult:
    result = CheckResult("files")
    roots = candidate_roots() if roots is None else roots
    names = indicators.by_kind("filename")
    hashes = indicators.by_kind("sha256")

    if not roots:
        result.gaps.append("no user-writable folders were found")
    hashing = bool(hashes) and not quick
    if hashes and quick:
        result.gaps.append("SHA-256 comparison skipped (--quick)")

    too_large = 0
    unreadable: List[str] = []
    skipped: List[str] = []
    for root in roots:
        in_root = 0
        for path in _walk(root, MAX_DEPTH, skipped if skip_caches else None):
            if in_root >= max_files:
                result.gaps.append(
                    f"stopped at {max_files} files in {root}; later files in that folder were not examined"
                )
                break
            if path.is_symlink():
                continue
            in_root += 1
            result.examined += 1
            if tick is not None and result.examined % 500 == 0:
                tick(result.examined)

            name_hit = names.get(path.name.lower())
            if name_hit is not None:
                result.findings.append(
                    make_finding("files", "name-lead", name_hit, str(path),
                                 "file name matches a campaign name; the name alone is weak evidence")
                )

            if not hashing:
                continue
            try:
                if path.stat().st_size > MAX_HASH_BYTES:
                    too_large += 1
                    continue
                digest = sha256_file(path)
            except OSError:
                unreadable.append(str(path))
                continue
            ind = hashes.get(digest)
            if ind is not None:
                result.findings.append(
                    make_finding("files", "file-match", ind, str(path), f"SHA-256 {digest}")
                )

    if skipped:
        shown = ", ".join(sorted({Path(p).name for p in skipped})[:6])
        result.gaps.append(
            f"{len(skipped)} cache or dependency folders were skipped ({shown}); use --deep to include them"
        )
    if too_large:
        result.gaps.append(f"{too_large} files over {MAX_HASH_BYTES // (1024 * 1024)} MB were not hashed")
    if unreadable:
        sample = "; ".join(unreadable[:_SAMPLE_UNREADABLE])
        more = len(unreadable) - _SAMPLE_UNREADABLE
        suffix = f" (and {more} more)" if more > 0 else ""
        result.gaps.append(f"{len(unreadable)} files could not be read: {sample}{suffix}")
    return result
