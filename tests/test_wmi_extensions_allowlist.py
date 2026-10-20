"""WMI/COM, browser extensions, shell history, macOS login items, and the allowlist."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scanner import allowlist
from scanner.checks_extensions import check_extensions
from scanner.checks_history import check_history
from scanner.checks_persistence import check_persistence, login_items_names
from scanner.checks_wmi import check_wmi, parse_wmi_consumers
from scanner.evidence import CheckResult, make_finding
from scanner.ioc import Indicator, IndicatorSet
from scanner.runner import ScanReport


def inds(kind, *values, tier="confirmed"):
    return IndicatorSet(Indicator(kind, v, tier, "high", "t") for v in values)


class WmiTests(unittest.TestCase):
    def test_parses_both_consumer_blocks(self):
        text = (
            '[{"Name":"Updater","CommandLineTemplate":"C:\\\\x\\\\evil.exe -q"}]\n'
            '[{"Name":"Script","ScriptFileName":"C:\\\\x\\\\evil2.exe"}]\n'
        )
        self.assertEqual(
            parse_wmi_consumers(text),
            [("Updater", "C:\\x\\evil.exe -q"), ("Script", "C:\\x\\evil2.exe")],
        )

    def test_empty_blocks_are_ignored(self):
        self.assertEqual(parse_wmi_consumers("[]\n[]\n"), [])

    def test_matches_consumer_and_clsid_override(self):
        class Proc:
            stdout = b'[{"Name":"Updater","CommandLineTemplate":"cmd /c evil.exe"}]\n[]\n'

        result = check_wmi(
            inds("filename", "evil.exe", "hijack.dll"), platform="win32",
            run=lambda *a, **k: Proc(),
            clsid_reader=lambda: [(r"HKCU\Software\Classes\CLSID\{x}\InprocServer32", r"C:\x\hijack.dll")],
        )
        grades = sorted(f.grade for f in result.findings)
        self.assertEqual(grades, ["com-hijack", "wmi-consumer"])

    def test_skipped_off_windows(self):
        self.assertEqual(check_wmi(inds("filename", "x"), platform="linux").status, "skipped")

    def test_command_failure_is_a_gap_not_a_crash(self):
        def boom(*a, **k):
            raise OSError("no powershell")

        result = check_wmi(inds("filename", "x"), platform="win32", run=boom, clsid_reader=lambda: [])
        self.assertTrue(any("WMI event subscriptions could not be read" in g for g in result.gaps))


class ExtensionTests(unittest.TestCase):
    def _chrome_profile(self, root: Path, ext_id: str, name: str):
        ext_dir = root / "Default" / "Extensions" / ext_id / "1.0"
        ext_dir.mkdir(parents=True)
        (ext_dir / "manifest.json").write_text(json.dumps({"name": name}))

    def test_matches_by_id_and_by_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            chrome = home / ".config" / "google-chrome"
            self._chrome_profile(chrome, "a" * 32, "Harmless Helper")
            self._chrome_profile(chrome, "b" * 32, "evil-campaign")
            indicators = IndicatorSet([
                Indicator("extension", "a" * 32, "confirmed", "high", "t"),
                Indicator("filename", "evil-campaign", "confirmed", "high", "t"),
            ])
            result = check_extensions(indicators, home=home, platform="linux")
        self.assertEqual(result.examined, 2)
        grades = sorted(f.grade for f in result.findings)
        self.assertEqual(grades, ["extension", "name-lead"])

    def test_firefox_addon_by_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            profile = home / ".mozilla" / "firefox" / "abc.default"
            profile.mkdir(parents=True)
            (profile / "extensions.json").write_text(json.dumps({"addons": [{"id": "evil@example.com"}]}))
            indicators = IndicatorSet([Indicator("extension", "evil@example.com", "confirmed", "high", "t")])
            result = check_extensions(indicators, home=home, platform="linux")
        self.assertEqual(len(result.findings), 1)

    def test_no_browsers_is_a_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = check_extensions(inds("extension", "x" * 32), home=Path(tmp), platform="linux")
        self.assertTrue(any("no browser extensions" in g for g in result.gaps))


class HistoryTests(unittest.TestCase):
    def test_finds_domain_and_filename_mentions(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".bash_history").write_text("curl http://evil.example/x\nls -la\nrun evil-tool.sh\n")
            indicators = IndicatorSet([
                Indicator("domain", "evil.example", "confirmed", "high", "t"),
                Indicator("filename", "evil-tool.sh", "confirmed", "high", "t"),
            ])
            result = check_history(indicators, home=home, platform="linux")
        values = sorted(f.indicator.value for f in result.findings)
        self.assertEqual(values, ["evil-tool.sh", "evil.example"])
        self.assertTrue(all(f.severity == "low" for f in result.findings))

    def test_no_history_files_is_a_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = check_history(inds("domain", "x.example"), home=Path(tmp), platform="linux")
        self.assertTrue(any("no shell or PowerShell history" in g for g in result.gaps))

    def test_oversized_file_is_skipped_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            path = home / ".bash_history"
            with mock.patch("scanner.checks_history._MAX_BYTES", 10):
                path.write_text("evil.example " * 5)
                result = check_history(inds("domain", "evil.example"), home=home, platform="linux")
        self.assertEqual(result.findings, [])


class LoginItemsTests(unittest.TestCase):
    def test_login_items_plist_parsed_and_matched(self):
        import plistlib

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            prefs = home / "Library" / "Preferences"
            prefs.mkdir(parents=True)
            with (prefs / "com.apple.loginitems.plist").open("wb") as fh:
                plistlib.dump({"SessionItems": {"CustomListItems": [{"Name": "Evil Helper"}]}}, fh)
            indicators = IndicatorSet([Indicator("filename", "evil helper", "confirmed", "high", "t")])
            result = check_persistence(indicators, home=home, platform="darwin")
        self.assertTrue(any(f.location == "login items" for f in result.findings))

    def test_helper_function_handles_missing_plist(self):
        with tempfile.TemporaryDirectory() as tmp:
            names, problems = login_items_names(Path(tmp))
        self.assertEqual(names, [])
        self.assertEqual(problems, [])


def _report_with_finding(check, grade, kind, value, location):
    ind = Indicator(kind, value, "confirmed", "high", "t")
    report = ScanReport(started="t", platform="p", indicator_count=1)
    result = CheckResult(check)
    result.findings.append(make_finding(check, grade, ind, location, "d"))
    report.results.append(result)
    return report, result.findings[0]


class AllowlistTests(unittest.TestCase):
    def test_add_persists_and_split_hides_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            report, finding = _report_with_finding("hosts", "hosts-config", "domain", "a.example", "h")
            allowlist.add(d, finding, note="known good")
            entries = allowlist.load(d)
            self.assertEqual(len(entries), 1)
            visible, allowed = allowlist.split(report, entries)
        self.assertEqual(visible, [])
        self.assertEqual(allowed, [finding])

    def test_remove_and_corrupt_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            report, finding = _report_with_finding("hosts", "hosts-config", "domain", "a.example", "h")
            entries = allowlist.add(d, finding)
            key = next(iter(entries))
            allowlist.remove(d, key)
            self.assertEqual(allowlist.load(d), {})
            (d / allowlist.CONFIG_NAME).write_text("{bad json")
            self.assertEqual(allowlist.load(d), {})

    def test_save_failure_returns_a_message(self):
        # A plain file where a directory is expected: mkdir(parents=True) fails on every OS.
        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "blocker"
            blocker.write_text("x")
            self.assertIsNotNone(allowlist.save(blocker, {}))

    def test_different_location_is_not_matched(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            report, finding = _report_with_finding("hosts", "hosts-config", "domain", "a.example", "h1")
            allowlist.add(d, finding)
            report2, finding2 = _report_with_finding("hosts", "hosts-config", "domain", "a.example", "h2")
            visible, allowed = allowlist.split(report2, allowlist.load(d))
        self.assertEqual(visible, [finding2])
        self.assertEqual(allowed, [])


if __name__ == "__main__":
    unittest.main()


class AllowlistMenuTests(unittest.TestCase):
    def test_mark_and_unmark_via_the_menu(self):
        import io
        import tempfile as tf
        from scanner.menu import App
        from scanner.ui import Console
        from tests.test_persistence_and_history import report_with, scripted

        feeds = Path(tf.mkdtemp())
        (feeds / "alpha.csv").write_text("kind,value,tier,confidence,source\ndomain,a.example,lead,high,t\n")
        reports = Path(tf.mkdtemp())
        out = io.StringIO()
        console = Console(out=out, read=scripted(
            ["2", "n", "", "5", "6", "a", "1", "benign", "0", "6", "r 1", "0", "0", "0"]
        ), color=False, width=80, clear=False, unicode=False)
        app = App(console, feeds_dir=feeds, reports_dir=reports)
        with mock.patch("scanner.menu.run_scan", return_value=report_with(("hosts", "hosts-config", "a.example", "h"))):
            app.run()
        text = out.getvalue()
        self.assertIn("Marked as reviewed", text)
        self.assertIn("Removed.", text)
        self.assertEqual(allowlist.load(reports), {})

    def test_report_hides_reviewed_finding(self):
        import io
        from scanner.menu import App
        from scanner.ui import Console
        from tests.test_persistence_and_history import report_with, scripted

        report = report_with(("hosts", "hosts-config", "a.example", "h"))
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            allowlist.add(reports, report.findings[0], "known good")
            out = io.StringIO()
            console = Console(out=out, read=scripted(["0"]), color=False, width=80, clear=False, unicode=False)
            app = App(console, reports_dir=reports)
            app.run()
            out.truncate(0); out.seek(0)
            app.show_report(report)
        text = out.getvalue()
        self.assertIn("1 finding(s) marked reviewed", text)
        self.assertIn("reviewed finding(s) hidden", text)
        self.assertIn("NO KNOWN INDICATOR FOUND", text)


class MenuVisibilityTests(unittest.TestCase):
    def app(self, inputs):
        import io
        import tempfile as tf
        from scanner.menu import App
        from scanner.ui import Console
        from tests.test_persistence_and_history import scripted

        feeds = Path(tf.mkdtemp())
        (feeds / "alpha.csv").write_text("kind,value,tier,confidence,source\ndomain,a.example,lead,high,t\n")
        out = io.StringIO()
        console = Console(out=out, read=scripted(inputs), color=False, width=90, clear=False, unicode=False)
        return App(console, feeds_dir=feeds, reports_dir=Path(tf.mkdtemp())), out

    def test_checks_screen_lists_every_check_with_platform_and_status(self):
        from scanner.runner import CHECK_NAMES

        app, out = self.app(["8", "", "0"])
        app.run()
        text = out.getvalue()
        self.assertIn(f"CHECKS ({len(CHECK_NAMES)})", text)
        for name in CHECK_NAMES:
            self.assertIn(name, text)
        self.assertIn("did not run", text)
        self.assertIn("Windows only", text)  # dns-cache / wmi

    def test_checks_screen_shows_last_scan_numbers(self):
        from unittest import mock
        from tests.test_persistence_and_history import report_with

        app, out = self.app(["2", "n", "", "8", "", "0"])
        with mock.patch("scanner.menu.run_scan", return_value=report_with(("hosts", "hosts-config", "a.example", "h"))):
            app.run()
        text = out.getvalue()
        self.assertIn("last scan: ran, examined", text)
        self.assertIn("1 finding(s)", text)

    def test_settings_dashboard_shows_feeds_reviewed_baseline_and_checks(self):
        app, out = self.app(["6", "0", "0"])
        app.run()
        text = out.getvalue()
        self.assertIn("CURRENT STATE", text)
        self.assertIn("indicators", text)
        self.assertIn("feeds switched on", text)
        self.assertIn("reviewed     0 finding(s)", text)
        self.assertIn("baseline     not set", text)
        self.assertIn("11 of 11 selected", text)

    def test_settings_dashboard_reflects_baseline_and_allowlist(self):
        from scanner import allowlist, baseline
        from tests.test_persistence_and_history import report_with

        app, out = self.app(["6", "0", "0"])
        report, finding = report_with(("hosts", "hosts-config", "a.example", "h")), None
        finding = report.findings[0]
        allowlist.add(app.reports_dir, finding)
        baseline.set_baseline(app.reports_dir, report)
        app.run()
        text = out.getvalue()
        self.assertIn("reviewed     1 finding(s)", text)
        self.assertIn("baseline     set", text)
