"""Locked-file copies, cache skipping, extra persistence sources, scan history and diff."""
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scanner import history
from scanner.checks_files import SKIP_DIR_NAMES, check_files
from scanner.checks_persistence import (
    check_persistence, command_names, cron_entries, scheduled_task_entries,
)
from scanner.evidence import CheckResult, make_finding
from scanner.fsutil import copy_file
from scanner.ioc import Indicator, IndicatorSet
from scanner.menu import App
from scanner.runner import ScanReport
from scanner.ui import Console


def inds(*names):
    return IndicatorSet(Indicator("filename", n, "confirmed", "high", "t") for n in names)


class LockedCopyTests(unittest.TestCase):
    def test_normal_copy_does_not_use_the_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dest = Path(tmp) / "a", Path(tmp) / "b"
            src.write_bytes(b"data")
            fallback = mock.Mock()
            copy_file(src, dest, platform="win32", shared_copy=fallback)
            self.assertEqual(dest.read_bytes(), b"data")
            fallback.assert_not_called()

    def test_locked_file_on_windows_uses_shared_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dest = Path(tmp) / "a", Path(tmp) / "b"
            src.write_bytes(b"data")
            fallback = mock.Mock()
            with mock.patch("scanner.fsutil.shutil.copy2", side_effect=PermissionError):
                copy_file(src, dest, platform="win32", shared_copy=fallback)
            fallback.assert_called_once_with(src, dest)

    def test_locked_file_elsewhere_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("scanner.fsutil.shutil.copy2", side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    copy_file(Path(tmp) / "a", Path(tmp) / "b", platform="linux")


class SmartFilesTests(unittest.TestCase):
    def make(self, root):
        (root / "Cache").mkdir()
        (root / "Cache" / "evil.bin").write_bytes(b"x")
        (root / "node_modules").mkdir()
        (root / "docs").mkdir()
        (root / "docs" / "evil.bin").write_bytes(b"x")

    def test_cache_folders_are_skipped_and_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make(root)
            result = check_files(inds("evil.bin"), roots=[root], quick=True)
        self.assertEqual([Path(f.location).parent.name for f in result.findings], ["docs"])
        self.assertTrue(any("2 cache or dependency folders were skipped" in g for g in result.gaps))

    def test_deep_includes_caches_and_has_no_skip_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make(root)
            result = check_files(inds("evil.bin"), roots=[root], quick=True, skip_caches=False)
        self.assertEqual(len(result.findings), 2)
        self.assertFalse(any("skipped (" in g for g in result.gaps))

    def test_skip_list_is_lowercase(self):
        self.assertTrue(all(n == n.lower() for n in SKIP_DIR_NAMES))


class CommandNamesTests(unittest.TestCase):
    def test_program_and_file_like_arguments(self):
        self.assertEqual(command_names(r'cmd.exe /c "C:\x\Payload.EXE" -q'), ["cmd.exe", "payload.exe"])
        self.assertEqual(command_names("/usr/bin/python3 /tmp/run.py --flag 5"), ["python3", "run.py"])

    def test_empty_and_numeric_tokens(self):
        self.assertEqual(command_names("   "), [])
        self.assertEqual(command_names("*/5 * * * * /bin/x"), [])  # schedule fields and bare words are not file names


TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions>
<Exec><Command>C:\\Windows\\System32\\cmd.exe</Command><Arguments>/c C:\\ProgramData\\evil.exe</Arguments></Exec>
</Actions></Task>"""


class PersistenceSourcesTests(unittest.TestCase):
    def test_scheduled_tasks_are_parsed_and_matched(self):
        with tempfile.TemporaryDirectory() as tmp:
            tasks = Path(tmp) / "Tasks"
            (tasks / "Sub").mkdir(parents=True)
            (tasks / "Sub" / "Updater").write_bytes(TASK_XML.encode("utf-16"))
            (tasks / "Broken").write_text("not xml")
            (tasks / "Bomb").write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><Task/>')
            entries, problems = scheduled_task_entries(tasks)
            self.assertEqual(len(entries), 1)
            self.assertTrue(any("2 scheduled-task definitions" in p for p in problems))
            result = check_persistence(
                inds("evil.exe"), platform="win32", win_reader=lambda k: [], hklm_reader=lambda k: [],
                services_reader=lambda: [], tasks_dir=tasks, startup_dirs=[],
            )
        self.assertEqual([f.grade for f in result.findings], ["autostart"])
        self.assertIn("Updater", result.findings[0].location)

    def test_services_hklm_and_startup_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            startup = Path(tmp) / "Startup"
            startup.mkdir()
            (startup / "evil.exe").write_bytes(b"x")
            (startup / "link.lnk").write_bytes("C:\\Users\\x\\hidden-drop.exe".encode("utf-16-le"))
            result = check_persistence(
                inds("evil.exe", "hidden-drop.exe", "svc.exe", "machine.exe"), platform="win32",
                win_reader=lambda k: [], hklm_reader=lambda k: [("m", r'"C:\a\machine.exe" /s')] if k.endswith("\\Run") else [],
                services_reader=lambda: [("Svc", r"C:\Windows\svc.exe -k x")],
                tasks_dir=Path(tmp) / "none", startup_dirs=[startup],
            )
        locations = sorted(f.location for f in result.findings)
        self.assertEqual(len(locations), 4)
        self.assertTrue(any(l.startswith("HKLM") for l in locations))
        self.assertIn("Service Svc", locations)

    def test_cron_lines(self):
        lines = [("user crontab", "# c"), ("user crontab", "MAILTO=x"), ("user crontab", "*/5 * * * * /tmp/evil.sh --x"),
                 ("/etc/crontab", "")]
        self.assertEqual(len(cron_entries(lines)), 1)
        with tempfile.TemporaryDirectory() as tmp:
            result = check_persistence(inds("evil.sh"), home=Path(tmp), platform="linux", cron_reader=lambda: (lines, []))
        self.assertEqual([f.location for f in result.findings], ["user crontab"])


def report_with(*findings, ran=("files", "hosts")):
    ind = lambda v: Indicator("domain", v, "confirmed", "high", "t")
    report = ScanReport(started="2026-01-02T00:00:00+00:00", platform="p", indicator_count=1)
    for name in ran:
        report.results.append(CheckResult(name))
    for check, grade, value, loc in findings:
        report.results[[r.name for r in report.results].index(check)].findings.append(
            make_finding(check, grade, ind(value), loc, "d"))
    return report


class HistoryTests(unittest.TestCase):
    def test_new_resolved_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = report_with(("hosts", "hosts-config", "a.example", "h"), ("hosts", "hosts-config", "b.example", "h"))
            history.save(Path(tmp), old)
            new = report_with(("hosts", "hosts-config", "b.example", "h"), ("files", "name-lead", "c.example", "f"))
            diff = history.compare(history.load_latest(Path(tmp)), new)
        self.assertEqual([f.indicator.value for f in diff.new], ["c.example"])
        self.assertEqual([r["value"] for r in diff.resolved], ["a.example"])
        self.assertEqual(diff.unchanged, 1)

    def test_check_that_did_not_run_is_not_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            history.save(Path(tmp), report_with(("hosts", "hosts-config", "a.example", "h")))
            diff = history.compare(history.load_latest(Path(tmp)), report_with(ran=("files",)))
        self.assertEqual(diff.resolved, [])
        self.assertEqual(diff.not_compared, ["hosts"])

    def test_corrupt_files_ignored_and_history_trimmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            self.assertIsNone(history.load_latest(d / "missing"))
            history.save(d, report_with())
            (d / "scan-99999999T000000000000Z.json").write_text("{bad")
            self.assertIsNotNone(history.load_latest(d))
            for _ in range(history.KEEP + 5):
                history.save(d, report_with())
            self.assertLessEqual(len(list(d.glob("scan-*.json"))), history.KEEP)


def scripted(items):
    q = list(items)
    def read(_p):
        if not q:
            raise EOFError
        return q.pop(0)
    return read


class MenuHistoryTests(unittest.TestCase):
    def test_second_scan_shows_changes(self):
        feeds = Path(tempfile.mkdtemp())
        (feeds / "alpha.csv").write_text("kind,value,tier,confidence,source\ndomain,a.example,lead,high,t\n")
        reports = Path(tempfile.mkdtemp())
        out = io.StringIO()
        console = Console(out=out, read=scripted(["2", "n", "", "2", "n", "", "6", "4", "0", "0"]), color=False, width=80, clear=False)
        app = App(console, feeds_dir=feeds, reports_dir=reports)
        reports_seq = [report_with(("hosts", "hosts-config", "a.example", "h")), report_with()]
        with mock.patch("scanner.menu.run_scan", side_effect=reports_seq):
            app.run()
        text = out.getvalue()
        self.assertIn("First recorded scan", text)
        self.assertIn("CHANGES SINCE", text)
        self.assertIn("RESOLVED", text)
        self.assertIn("Deep file scan is now on", text)
        self.assertTrue(app.deep)


if __name__ == "__main__":
    unittest.main()
