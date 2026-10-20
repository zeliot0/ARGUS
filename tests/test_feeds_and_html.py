"""Multi-feed support, the feed manager, the HTML report, progress output and CLI flags."""
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scanner.__main__ import main as cli_main
from scanner.checks_files import check_files
from scanner.evidence import CheckResult, make_finding
from scanner.feeds import CONFIG_NAME, build_set, discover_feeds, load_disabled, save_disabled
from scanner.ioc import Indicator, IndicatorSet, load_indicators, merge_indicators
from scanner.menu import App, parse_feed_tokens
from scanner.report_html import render_html
from scanner.runner import CHECK_NAMES, ScanReport
from scanner.ui import Console

ROOT = Path(__file__).resolve().parent.parent
IOCS = ROOT / "iocs"
HEADER = "kind,value,tier,confidence,source\n"


def write_feed(path: Path, *rows: str) -> Path:
    path.write_text(HEADER + "\n".join(rows) + "\n", encoding="utf-8")
    return path


def scripted(inputs):
    queue = list(inputs)

    def read(_prompt):
        if not queue:
            raise EOFError
        return queue.pop(0)

    return read


def make_app(inputs, feeds_dir, reports=None):
    out = io.StringIO()
    console = Console(out=out, read=scripted(inputs), color=False, width=80, clear=False)
    return App(console, feeds_dir=feeds_dir, reports_dir=reports or Path(tempfile.mkdtemp())), out


class MergeTests(unittest.TestCase):
    def test_campaign_comes_from_the_file_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = write_feed(Path(tmp) / "my-campaign.csv", "domain,a.example,lead,high,t")
            self.assertEqual(load_indicators(feed)[0].campaign, "my-campaign")

    def test_duplicates_keep_every_campaign_and_the_stronger_tier(self):
        a = [Indicator("domain", "x.example", "lead", "high", "src-a", "alpha")]
        b = [Indicator("domain", "x.example", "confirmed", "high", "src-b", "beta"), Indicator("ip", "203.0.113.1", "lead", "high", "s", "beta")]
        merged = {(i.kind, i.value): i for i in merge_indicators([a, b])}
        self.assertEqual(len(merged), 2)
        x = merged[("domain", "x.example")]
        self.assertEqual(x.tier, "confirmed")
        self.assertEqual(x.campaign, "alpha; beta")
        self.assertIn("src-a", x.source)
        self.assertIn("src-b", x.source)

    def test_punycode_tld_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = write_feed(Path(tmp) / "f.csv", "domain,example.xn--p1ai,lead,high,t")
            self.assertEqual(load_indicators(feed)[0].value, "example.xn--p1ai")


class DiscoveryTests(unittest.TestCase):
    def test_discovery_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            write_feed(d / "alpha.csv", "domain,a.example,lead,high,t")
            write_feed(d / "phishing-x.csv", "domain,p.example,lead,high,t")
            write_feed(d / "sample.csv", "domain,s.example,lead,high,t")
            write_feed(d / "unverified-candidates.csv", "domain,u.example,lead,high,t")
            (d / "broken.csv").write_text(HEADER + "url,x,lead,high,t\n")
            feeds = {f.name: f for f in discover_feeds(d)}
        self.assertEqual(set(feeds), {"alpha", "phishing-x", "broken"})  # sample + unverified never load
        self.assertTrue(feeds["alpha"].enabled)
        self.assertFalse(feeds["phishing-x"].enabled)  # phishing lists start off
        self.assertIsNotNone(feeds["broken"].error)
        self.assertFalse(feeds["broken"].enabled)

    def test_config_round_trip_and_bad_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            write_feed(d / "phishing-x.csv", "domain,p.example,lead,high,t")
            self.assertEqual(load_disabled(d), {"phishing-x"})
            self.assertIsNone(save_disabled(d, {"alpha"}))
            self.assertEqual(load_disabled(d), {"alpha"})
            (d / CONFIG_NAME).write_text("{not json")
            self.assertEqual(load_disabled(d), {"phishing-x"})  # falls back to the default

    def test_save_failure_returns_a_message(self):
        self.assertIn("could not save", save_disabled(Path("/no/such/dir"), set()))

    def test_nothing_switched_on_gives_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            write_feed(d / "alpha.csv", "domain,a.example,lead,high,t")
            self.assertIsNone(build_set(discover_feeds(d, disabled={"alpha"})))


class ShippedFeedsTests(unittest.TestCase):
    SHARED = set("""herokuapp.com azurewebsites.net cloudfront.net amazonaws.com appspot.com duckdns.org no-ip.com zapto.org ddns.net
        dyndns.org hopto.org blogspot.com wordpress.com github.io firebaseapp.com web.app workers.dev pages.dev netlify.app
        googleapis.com google.com facebook.com twitter.com youtube.com microsoft.com live.com outlook.com apple.com icloud.com
        dropbox.com cloudflare.com akamai.net fastly.net windows.net""".split())

    def setUp(self):
        self.feeds = discover_feeds(IOCS)
        self.by_name = {f.name: f for f in self.feeds}

    def test_expected_feeds_present_and_phishing_off(self):
        for name in ("adfection", "pegasus-nso", "predator-cytrox", "finfisher-2020", "donot-2021", "wintego-helios-2024",
                     "novispy-serbia-2024", "android-campaign-2023", "vietnam-2021", "india-2020", "uzbekistan-2020", "qatar-2021"):
            self.assertIn(name, self.by_name)
            self.assertTrue(self.by_name[name].enabled, name)
        for name in ("phishing-best-practice-2018", "phishing-egypt-oauth-2019", "phishing-evolving-2019"):
            self.assertFalse(self.by_name[name].enabled, name)
        self.assertTrue(all(f.error is None for f in self.feeds))

    def test_no_shared_platform_apex_in_any_feed(self):
        for f in self.feeds:
            for ind in f.indicators:
                if ind.kind == "domain":
                    self.assertNotIn(ind.value, self.SHARED, f"{f.name}: {ind.value}")

    def test_every_row_has_a_source_and_amnesty_rows_credit_the_licence(self):
        for f in self.feeds:
            for ind in f.indicators:
                self.assertTrue(ind.source, f"{f.name}: {ind.value}")
                if f.name != "adfection":
                    self.assertIn("CC-BY", ind.source)

    def test_hashes_are_confirmed_and_network_indicators_are_leads_in_amnesty_feeds(self):
        for f in self.feeds:
            if f.name == "adfection":
                continue
            for ind in f.indicators:
                self.assertEqual(ind.tier, "confirmed" if ind.kind == "sha256" else "lead", f"{f.name}: {ind.value}")

    def test_merged_set_is_large_and_has_a_known_pegasus_domain(self):
        merged = build_set(self.feeds)
        self.assertGreater(len(merged), 5000)
        self.assertIsNotNone(merged.get("domain", "fearevolve.com"))
        self.assertIsNotNone(merged.find_host("sub.123tramites.com"))


class FeedManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        write_feed(self.d / "alpha.csv", "domain,a.example,lead,high,t")
        write_feed(self.d / "beta.csv", "domain,b.example,lead,high,t", "ip,203.0.113.9,lead,high,t")
        write_feed(self.d / "phishing-x.csv", "domain,p.example,lead,high,t")

    def tearDown(self):
        self.tmp.cleanup()

    def test_parse_feed_tokens(self):
        self.assertEqual(parse_feed_tokens("2 alpha", ["alpha", "beta"]), ["beta", "alpha"])
        for bad in ("9", "nope", ""):
            with self.assertRaises(ValueError):
                parse_feed_tokens(bad, ["alpha", "beta"])

    def test_header_and_defaults(self):
        app, out = make_app(["0"], self.d)
        app.run()
        self.assertIn("2 of 3 switched on", out.getvalue())
        self.assertEqual(len(app.indicators), 3)

    def test_toggle_a_feed_saves_and_rebuilds(self):
        app, out = make_app(["4", "3", "1", "", "0", "0"], self.d)
        app.run()
        self.assertEqual(len(app.indicators), 2)  # alpha off, beta's two remain
        saved = json.loads((self.d / CONFIG_NAME).read_text())
        self.assertEqual(set(saved["disabled"]), {"alpha", "phishing-x"})

    def test_all_none_and_bad_input(self):
        app, out = make_app(["4", "3", "none", "", "0", "0"], self.d)
        app.run()
        self.assertIsNone(app.indicators)
        self.assertIn("Nothing is switched on", out.getvalue())
        app, out = make_app(["4", "3", "9", "all", "", "0", "0"], self.d)
        app.run()
        self.assertIn("there is no feed number 9", out.getvalue())
        self.assertEqual(len(app.indicators), 4)  # everything on, phishing included

    def test_unreadable_feed_is_flagged_and_cannot_be_switched_on(self):
        (self.d / "bad.csv").write_text(HEADER + "url,x,lead,high,t\n")
        app, out = make_app(["4", "3", "all", "", "0", "0"], self.d)
        app.run()
        self.assertIn("unreadable", out.getvalue())
        self.assertEqual(len(app.indicators), 4)

    def test_loading_a_csv_replaces_feeds_until_reload(self):
        one = write_feed(self.d / "solo.csv", "domain,solo.example,lead,high,t")
        # solo.csv lives in the feeds folder too, so move the app to a clean folder for clarity
        app, out = make_app(["4", "1", str(one), "3", "4", "0", "0"], self.d)
        app.run()
        self.assertIn("A CSV was loaded by hand", out.getvalue())
        self.assertIsNone(app.source_file)  # "Reload feeds" returned to the folder
        self.assertGreater(len(app.indicators), 1)

    def test_empty_folder_message(self):
        with tempfile.TemporaryDirectory() as empty:
            app, out = make_app(["0"], Path(empty))
            app.run()
        self.assertIn("no feed files found", out.getvalue())


def hostile_report():
    ind = Indicator("domain", "evil.example", "confirmed", "high", 'src & <i>tag</i>', 'camp"aign')
    result = CheckResult("files", examined=1500)
    result.findings.append(
        make_finding("files", "name-lead", ind, r"C:\Users\x\<script>alert(1)</script>.exe", '"><img src=x onerror=alert(1)>')
    )
    result.gaps.append("<b>gap</b> & more")
    report = ScanReport(started="2026-01-01T00:00:00+00:00", platform="<Win>", indicator_count=3, results=[result])
    report.not_run = ["browser"]
    return report


class HtmlReportTests(unittest.TestCase):
    def test_hostile_values_are_escaped(self):
        html = render_html(hostile_report())
        self.assertNotIn("<script", html.lower())
        self.assertNotIn("<img", html.lower())
        self.assertNotIn("<i>tag", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn("&quot;&gt;&lt;img", html)
        self.assertIn("evil[.]example", html)  # defanged

    def test_page_is_self_contained(self):
        html = render_html(hostile_report())
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("default-src 'none'", html)
        self.assertIsNone(re.search(r"<[^>]*\b(src|href)\s*=", html))  # no real tag loads anything
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)

    def test_counts_and_sections(self):
        html = render_html(hostile_report())
        self.assertIn("Findings (1)", html)
        self.assertIn("Could not check (", html)
        self.assertIn("not run", html)
        clean = render_html(ScanReport(started="t", platform="p", indicator_count=1, results=[CheckResult("hosts")]))
        self.assertIn("No known indicator found", clean)
        self.assertIn("None.", clean)


class ReportUiTests(unittest.TestCase):
    def feed(self):
        d = tempfile.mkdtemp()
        write_feed(Path(d) / "alpha.csv", "domain,a.example,lead,high,t")
        return Path(d)

    def test_progress_shows_bar_count_and_timing(self):
        def fake_run(indicators, quick=False, max_files=0, only=None, progress=None, tick=None, deep=False):
            report = ScanReport(started="t", platform="p", indicator_count=1)
            for name in only:
                progress("start", name, None)
                result = CheckResult(name, examined=7)
                progress("done", name, result)
                report.results.append(result)
            return report

        app, out = make_app(["2", "n", "", "0"], self.feed())
        with mock.patch("scanner.menu.run_scan", side_effect=fake_run):
            app.run()
        text = out.getvalue()
        self.assertIn("1/%d" % len(CHECK_NAMES), text)
        self.assertIn("%d/%d" % (len(CHECK_NAMES), len(CHECK_NAMES)), text)
        self.assertIn("[##########]", text)
        self.assertRegex(text, r"\d+\.\ds")

    def test_dashboard_lists_every_severity(self):
        app, out = make_app(["0"], self.feed())
        app.run()
        out.truncate(0)
        app.show_report(hostile_report())
        text = out.getvalue()
        self.assertIn("SEVERITY", text)
        for sev in ("high", "medium", "low", "info"):
            self.assertRegex(text, rf"{sev}\s+[#-]{{20}} \d")

    def test_save_writes_html_and_open_uses_the_browser(self):
        reports = Path(tempfile.mkdtemp())
        app, out = make_app(["5", "4", "2", "4", "0", "0"], self.feed(), reports=reports)
        app.report = hostile_report()
        with mock.patch("scanner.menu.webbrowser.open", return_value=True) as opener:
            app.run()
        self.assertIn("No HTML report yet", out.getvalue())  # first "open" before any save
        opener.assert_called_once()
        self.assertTrue(opener.call_args.args[0].startswith("file://"))
        self.assertEqual(len(list(reports.glob("*.html"))), 1)

    def test_open_reports_failure_when_no_browser(self):
        reports = Path(tempfile.mkdtemp())
        (reports / "argus-20260101-000000.html").write_text("<html></html>")
        app, out = make_app(["5", "4", "0", "0"], self.feed(), reports=reports)
        with mock.patch("scanner.menu.webbrowser.open", return_value=False):
            app.run()
        self.assertIn("Could not start a browser", out.getvalue())


class TickTests(unittest.TestCase):
    def test_tick_called_every_500_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for i in range(1200):
                (root / f"f{i}.dat").write_bytes(b"x")
            ticks = []
            check_files(IndicatorSet([Indicator("filename", "zzz", "lead", "high", "t")]), roots=[root], quick=True, tick=ticks.append)
        self.assertEqual(ticks, [500, 1000])


class CliFlagTests(unittest.TestCase):
    def test_one_of_ioc_or_feeds_is_required(self):
        with self.assertRaises(SystemExit) as ctx, mock.patch("sys.stderr", io.StringIO()):
            cli_main([])
        self.assertEqual(ctx.exception.code, 2)

    def test_ioc_can_be_repeated_and_is_merged(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = write_feed(Path(tmp) / "a.csv", "domain,a.example,lead,high,t")
            b = write_feed(Path(tmp) / "b.csv", "domain,a.example,confirmed,high,t", "domain,b.example,lead,high,t")
            with mock.patch("scanner.__main__.run_scan") as run, mock.patch("sys.stdout", io.StringIO()):
                run.return_value = ScanReport(started="t", platform="p", indicator_count=2)
                code = cli_main(["--ioc", str(a), "--ioc", str(b), "--quick"])
        self.assertEqual(code, 0)
        indicators = run.call_args.args[0]
        self.assertEqual(len(indicators), 2)
        self.assertEqual(indicators.get("domain", "a.example").tier, "confirmed")

    def test_feeds_flag_uses_the_feeds_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_feed(Path(tmp) / "alpha.csv", "domain,a.example,lead,high,t")
            with mock.patch("scanner.__main__.DEFAULT_FEEDS_DIR", Path(tmp)), \
                 mock.patch("scanner.__main__.run_scan") as run, mock.patch("sys.stdout", io.StringIO()):
                run.return_value = ScanReport(started="t", platform="p", indicator_count=1)
                self.assertEqual(cli_main(["--feeds"]), 0)
        self.assertEqual(len(run.call_args.args[0]), 1)

    def test_feeds_flag_with_nothing_on_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            err = io.StringIO()
            with mock.patch("scanner.__main__.DEFAULT_FEEDS_DIR", Path(tmp)), mock.patch("sys.stderr", err):
                self.assertEqual(cli_main(["--feeds"]), 1)
        self.assertIn("no feeds are switched on", err.getvalue())


if __name__ == "__main__":
    unittest.main()
