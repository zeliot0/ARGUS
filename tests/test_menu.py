import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scanner.evidence import CheckResult, make_finding
from scanner.ioc import Indicator, IndicatorSet
from scanner.menu import CHECK_NAMES, App, is_placeholder, parse_selection
from scanner.runner import ScanReport, run_scan
from scanner.ui import Console

SAMPLE = Path(__file__).resolve().parent.parent / "iocs" / "sample.csv"


def scripted(inputs):
    """Stand-in for input(): returns each scripted line, then raises EOFError like Ctrl-D."""
    queue = list(inputs)

    def read(_prompt):
        if not queue:
            raise EOFError
        return queue.pop(0)

    return read


def make_app(inputs, feed=SAMPLE, reports=None, width=80):
    out = io.StringIO()
    console = Console(out=out, read=scripted(inputs), color=False, width=width, clear=False)
    app = App(console, feed_path=feed, reports_dir=reports or Path(tempfile.mkdtemp()))
    return app, out


def fake_report(with_finding=False):
    report = ScanReport(started="2026-01-01T00:00:00+00:00", platform="Test 1", indicator_count=4)
    result = CheckResult("files", examined=1234, gaps=["something was skipped"])
    if with_finding:
        ind = Indicator("sha256", "a" * 64, "confirmed", "high", "test source")
        result.findings.append(make_finding("files", "file-match", ind, "C:\\temp\\x.bin", "SHA-256 " + "a" * 64))
    report.results.append(result)
    report.not_run = ["browser"]
    return report


class ParseSelectionTests(unittest.TestCase):
    def test_numbers_names_and_all(self):
        self.assertEqual(parse_selection("1 3", CHECK_NAMES), ["browser", "persistence"])
        self.assertEqual(parse_selection("3,1", CHECK_NAMES), ["browser", "persistence"])
        self.assertEqual(parse_selection("hosts browser", CHECK_NAMES), ["browser", "hosts"])
        self.assertEqual(parse_selection("ALL", CHECK_NAMES), list(CHECK_NAMES))

    def test_rejects_bad_input(self):
        for bad in ("0", "99", "nonsense", "", "1 x"):
            with self.assertRaises(ValueError, msg=bad):
                parse_selection(bad, CHECK_NAMES)


class RunnerSelectionTests(unittest.TestCase):
    def test_only_runs_selected_and_reports_the_rest_as_not_run(self):
        ind = IndicatorSet([Indicator("domain", "evil.example", "confirmed", "high", "t")])
        events = []
        report = run_scan(ind, quick=True, only=["hosts"], progress=lambda e, n, r: events.append((e, n)))
        self.assertEqual([r.name for r in report.results], ["hosts"])
        self.assertEqual(events, [("start", "hosts"), ("done", "hosts")])
        self.assertIn("browser", report.not_run)
        self.assertTrue(any(name == "browser" and "not selected" in text for name, text in report.gaps))
        self.assertFalse(report.complete)

    def test_unknown_check_is_rejected(self):
        with self.assertRaises(ValueError):
            run_scan(IndicatorSet([]), only=["nope"])


class MenuFlowTests(unittest.TestCase):
    def test_exit(self):
        app, out = make_app(["0"])
        self.assertEqual(app.run(), 0)
        self.assertIn("MAIN MENU", out.getvalue())
        self.assertIn("Goodbye.", out.getvalue())

    def test_invalid_choice_reprompts(self):
        app, out = make_app(["x", "99", "0"])
        app.run()
        self.assertEqual(out.getvalue().count("Not a valid choice"), 2)

    def test_eof_and_ctrl_c_exit_cleanly(self):
        app, _ = make_app([])  # EOF straight away
        self.assertEqual(app.run(), 0)

        def interrupt(_prompt):
            raise KeyboardInterrupt

        out = io.StringIO()
        app = App(Console(out=out, read=interrupt, color=False, width=80, clear=False), feed_path=SAMPLE)
        self.assertEqual(app.run(), 0)

    def test_placeholder_feed_is_flagged_in_header(self):
        app, out = make_app(["0"])
        app.run()
        self.assertIn("PLACEHOLDER DATA", out.getvalue())
        self.assertTrue(is_placeholder(app.indicators))

    def test_quick_scan_shows_findings_and_does_not_save_on_no(self):
        reports = Path(tempfile.mkdtemp())
        app, out = make_app(["2", "n", "", "0"], reports=reports)
        with mock.patch("scanner.menu.run_scan", return_value=fake_report(True)) as run:
            app.run()
        self.assertTrue(run.call_args.kwargs["quick"])
        text = out.getvalue()
        self.assertIn("INDICATOR MATCHES FOUND", text)
        self.assertIn("[HIGH]", text)
        self.assertIn("COULD NOT CHECK", text)
        self.assertEqual([p.name for p in reports.iterdir()], ["history"])  # only the scan history, no report files

    def test_full_scan_hashes_and_save_writes_text_json_and_html(self):
        reports = Path(tempfile.mkdtemp())
        app, out = make_app(["1", "y", "", "0"], reports=reports)
        with mock.patch("scanner.menu.run_scan", return_value=fake_report(True)) as run:
            app.run()
        self.assertFalse(run.call_args.kwargs["quick"])
        names = sorted(p.suffix for p in reports.iterdir() if p.is_file())
        self.assertEqual(names, [".html", ".json", ".txt"])
        data = json.loads(next(reports.glob("*.json")).read_text(encoding="utf-8"))
        self.assertEqual(data["indicator_count"], 4)
        self.assertIn("Saved", out.getvalue())

    def test_custom_scan_passes_selection_through(self):
        app, _ = make_app(["3", "1 3", "n", "", "0"])
        with mock.patch("scanner.menu.run_scan", return_value=fake_report()) as run:
            app.run()
        self.assertEqual(run.call_args.kwargs["only"], ["browser", "persistence"])

    def test_custom_scan_reprompts_on_bad_selection(self):
        app, out = make_app(["3", "zzz", "2", "n", "", "0"])
        with mock.patch("scanner.menu.run_scan", return_value=fake_report()) as run:
            app.run()
        self.assertIn("unknown check", out.getvalue())
        self.assertEqual(run.call_args.kwargs["only"], ["files"])

    def test_scan_refuses_without_a_feed(self):
        app, out = make_app(["1", "", "0"], feed=Path("/no/such/feed.csv"))
        with mock.patch("scanner.menu.run_scan") as run:
            app.run()
        run.assert_not_called()
        self.assertIn("No indicator feed is loaded", out.getvalue())

    def test_ctrl_c_during_scan_cancels_without_keeping_a_report(self):
        app, out = make_app(["1", "", "0"])
        with mock.patch("scanner.menu.run_scan", side_effect=KeyboardInterrupt):
            app.run()
        self.assertIn("Scan cancelled", out.getvalue())
        self.assertIsNone(app.report)

    def test_bad_feed_path_keeps_the_old_feed(self):
        app, out = make_app(["4", "1", "/no/such/file.csv", "0", "0"])
        app.run()
        self.assertIn("cannot read", out.getvalue())
        self.assertEqual(len(app.indicators), 4)

    def test_feed_path_with_quotes_is_accepted(self):
        app, out = make_app(["4", "1", f'"{SAMPLE}"', "0", "0"])
        app.run()
        self.assertIn("Loaded 4 indicators", out.getvalue())

    def test_settings_validation(self):
        app, out = make_app(["6", "1", "abc", "1", "5", "1", "1,500", "2", "0", "0"])
        app.run()
        self.assertEqual(app.max_files, 1500)  # '1,500' is read as 1500
        self.assertFalse(app.hash_files)
        self.assertEqual(out.getvalue().count("Enter a whole number"), 2)

    def test_reports_menu_without_a_scan(self):
        app, out = make_app(["5", "1", "2", "3", "0", "0"])
        app.run()
        self.assertIn("There is no scan yet", out.getvalue())
        self.assertIn("No saved reports", out.getvalue())

    def test_about_screen(self):
        app, out = make_app(["7", "", "0"])
        app.run()
        self.assertIn("not a clean bill of health", out.getvalue())


class ConsoleTests(unittest.TestCase):
    def test_colour_off_has_no_escape_codes(self):
        console = Console(out=io.StringIO(), color=False)
        self.assertEqual(console.paint("hi", "red"), "hi")

    def test_colour_on_wraps_text(self):
        console = Console(out=io.StringIO(), color=True)
        self.assertEqual(console.paint("hi", "red"), "\x1b[31mhi\x1b[0m")

    def test_box_lines_are_all_the_same_width(self):
        out = io.StringIO()
        Console(out=out, color=False, width=40).box(["a short line", "", "x " * 60])
        widths = {len(line) for line in out.getvalue().splitlines()}
        self.assertEqual(widths, {40})

    def test_narrow_terminal_does_not_crash(self):
        out = io.StringIO()
        console = Console(out=out, color=False, width=20)
        console.box(["tiny"])
        self.assertTrue(out.getvalue())

    def test_no_non_ascii_in_banner(self):
        from scanner.ui import BANNER

        for line in BANNER:
            line.encode("ascii")


if __name__ == "__main__":
    unittest.main()
