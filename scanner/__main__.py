"""Command line entry point: argus.py (--ioc FILE ... | --feeds) [--quick] [--json PATH]"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__, netguard
from .checks_files import MAX_FILES
from .feeds import DEFAULT_FEEDS_DIR, build_set, discover_feeds
from .ioc import IOCError, IndicatorSet, load_indicators, merge_indicators
from .report import render_text
from .runner import run_scan
from .ui import safe_console


def main(argv=None) -> int:
    netguard.install()
    safe_console()
    parser = argparse.ArgumentParser(
        prog="argus",
        description="Read-only, offline check of this computer for published indicators.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--ioc", action="append", metavar="FILE", help="indicator CSV; repeat to combine several")
    source.add_argument("--feeds", action="store_true", help="use the feeds switched on in iocs/ (change them in the ARGUS menu)")
    parser.add_argument("--quick", action="store_true", help="skip SHA-256 comparison of file contents")
    parser.add_argument("--max-files", type=int, default=MAX_FILES, metavar="N", help="files to examine per folder (default %(default)s)")
    parser.add_argument("--deep", action="store_true", help="also walk cache and dependency folders (slower)")
    parser.add_argument("--json", metavar="PATH", help="also write a JSON report (contains raw indicator values)")
    args = parser.parse_args(argv)

    try:
        if args.feeds:
            indicators = build_set(discover_feeds(DEFAULT_FEEDS_DIR))
            if indicators is None:
                raise IOCError("no feeds are switched on, or none were found in iocs/")
        else:
            indicators = IndicatorSet(merge_indicators([load_indicators(p) for p in args.ioc]))
    except IOCError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    report = run_scan(indicators, quick=args.quick, max_files=args.max_files, deep=args.deep)
    print(render_text(report))

    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(report.to_dict(), fh, indent=2)
        except OSError as exc:
            print(f"error: cannot write {args.json}: {exc}", file=sys.stderr)
            return 1
    return report.exit_code()


if __name__ == "__main__":
    sys.exit(main())
