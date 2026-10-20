import hashlib
import io
import json
import plistlib
import socket
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from scanner import netguard
from scanner.__main__ import main
from scanner.checks_browser import CHROME_COOKIE_SQL, check_browsers, chromium_time, firefox_time
from scanner.checks_files import check_files
from scanner.checks_network import check_dns_cache, check_hosts, decode_console, parse_hosts
from scanner.checks_persistence import (
    WINDOWS_RUN_KEYS,
    check_persistence,
    command_basename,
    launchd_entries,
    windows_run_entries,
)
from scanner.evidence import CheckResult, make_finding, severity_for
from scanner.ioc import IOCError, Indicator, IndicatorSet, load_indicators, normalize_value
from scanner.report import defang, render_text
from scanner.runner import ScanReport

SAMPLE = Path(__file__).resolve().parent.parent / "iocs" / "sample.csv"


def _indicators(*rows):
    return IndicatorSet(
        Indicator(kind=k, value=v, tier=t, confidence="high", source="test") for k, v, t in rows
    )


def _report(*results):
    report = ScanReport(started="now", platform="test", indicator_count=1)
    report.results.extend(results)
    return report


class NetworkGuardTests(unittest.TestCase):
    def test_connect_is_blocked(self):
        netguard.install()
        with self.assertRaises(netguard.NetworkAttempt):
            socket.create_connection(("127.0.0.1", 9), timeout=1)

    def test_dns_lookup_is_blocked(self):
        netguard.install()
        with self.assertRaises(netguard.NetworkAttempt):
            socket.getaddrinfo("example.invalid", 80)


class IOCTests(unittest.TestCase):
    def test_sample_file_loads(self):
        inds = load_indicators(SAMPLE)
        self.assertEqual({i.kind for i in inds}, {"domain", "ip", "sha256", "filename"})

    def test_bom_and_crlf_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.csv"
            path.write_bytes(
                "\ufeffkind,value,tier,confidence,source\r\ndomain,evil.example,confirmed,high,t\r\n".encode("utf-8")
            )
            self.assertEqual(load_indicators(path)[0].value, "evil.example")

    def test_domain_matches_subdomain_but_not_lookalike(self):
        ind = _indicators(("domain", "evil.example", "confirmed"))
        self.assertIsNotNone(ind.find_host("evil.example"))
        self.assertIsNotNone(ind.find_host("a.b.evil.example"))
        self.assertIsNone(ind.find_host("notevil.example"))
        self.assertIsNone(ind.find_host("evil.example.org"))

    def test_normalisation(self):
        self.assertEqual(normalize_value("domain", " Evil.Example. "), "evil.example")
        self.assertEqual(normalize_value("sha256", "AB" * 32), "ab" * 32)

    def test_rejects_bad_values(self):
        with self.assertRaises(IOCError):
            normalize_value("domain", "not a domain")
        with self.assertRaises(IOCError):
            normalize_value("filename", "dir/file.exe")
        with self.assertRaises(IOCError):
            normalize_value("sha256", "abc")

    def test_rejects_unknown_kind_and_tier_with_line_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.csv"
            bad.write_text("kind,value,tier,confidence,source\nurl,x,confirmed,high,t\n")
            with self.assertRaisesRegex(IOCError, "line 2"):
                load_indicators(bad)
            bad.write_text("kind,value,tier,confidence,source\ndomain,evil.example,maybe,high,t\n")
            with self.assertRaises(IOCError):
                load_indicators(bad)

    def test_missing_file_is_ioc_error(self):
        with self.assertRaises(IOCError):
            load_indicators("does-not-exist.csv")


class EvidenceTests(unittest.TestCase):
    def test_lead_tier_is_downgraded(self):
        self.assertEqual(severity_for("file-match", "confirmed"), "high")
        self.assertEqual(severity_for("file-match", "lead"), "medium")
        self.assertEqual(severity_for("hosts-sink", "lead"), "info")

    def test_unknown_grade_rejected(self):
        ind = Indicator("domain", "evil.example", "confirmed", "high", "t")
        with self.assertRaises(ValueError):
            make_finding("x", "made-up", ind, "loc", "detail")


class TimestampTests(unittest.TestCase):
    def test_chromium_epoch_is_1970(self):
        self.assertEqual(chromium_time(11644473600 * 1_000_000), "1970-01-01T00:00:00+00:00")

    def test_firefox_one_second(self):
        self.assertEqual(firefox_time(1_000_000), "1970-01-01T00:00:01+00:00")

    def test_zero_and_none_are_unknown(self):
        self.assertIsNone(chromium_time(0))
        self.assertIsNone(firefox_time(None))


class BrowserTests(unittest.TestCase):
    def _make_chromium_profile(self, home: Path):
        profile = home / ".config" / "google-chrome" / "Default"
        profile.mkdir(parents=True)
        conn = sqlite3.connect(profile / "History")
        conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, last_visit_time INTEGER)")
        conn.execute(
            "INSERT INTO urls (url, last_visit_time) VALUES (?, ?)",
            ("https://tracker.example.invalid/ad?x=1", 13300000000000000),
        )
        conn.commit()
        conn.close()
        conn = sqlite3.connect(profile / "Cookies")
        conn.execute(
            "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, last_access_utc INTEGER)"
        )
        conn.execute(
            "INSERT INTO cookies VALUES (?, ?, ?, ?, ?)",
            (".tracker.example.invalid", "id", "SECRET-COOKIE-VALUE", None, 13300000000000000),
        )
        conn.commit()
        conn.close()

    def test_visit_and_cookie_found_without_values(self):
        indicators = IndicatorSet(load_indicators(SAMPLE))
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            self._make_chromium_profile(home)
            result = check_browsers(indicators, home=home, platform="linux")
        self.assertEqual(sorted(f.grade for f in result.findings), ["cookie-lead", "visit"])
        for finding in result.findings:
            self.assertNotIn("SECRET-COOKIE-VALUE", finding.detail)
            self.assertNotIn("SECRET-COOKIE-VALUE", finding.location)

    def test_cookie_query_selects_no_values(self):
        self.assertNotIn("value", CHROME_COOKIE_SQL.lower())
        self.assertNotIn("encrypted", CHROME_COOKIE_SQL.lower())

    def test_no_profiles_is_a_gap_not_a_clean_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = check_browsers(IndicatorSet([]), home=Path(tmp), platform="linux")
        self.assertTrue(any("no supported browser profiles" in g for g in result.gaps))

    def test_corrupt_database_is_a_gap_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            profile = home / ".config" / "google-chrome" / "Default"
            profile.mkdir(parents=True)
            (profile / "History").write_bytes(b"this is not sqlite" * 100)
            result = check_browsers(IndicatorSet(load_indicators(SAMPLE)), home=home, platform="linux")
        self.assertEqual(result.findings, [])
        self.assertTrue(any("unreadable" in g for g in result.gaps))


class FileTests(unittest.TestCase):
    def test_hash_match_and_name_lead(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = b"planted test payload"
            (root / "sample.bin").write_bytes(payload)
            (root / "tracker-helper").write_bytes(b"x")
            digest = hashlib.sha256(payload).hexdigest()
            ind = _indicators(("sha256", digest, "confirmed"), ("filename", "tracker-helper", "confirmed"))
            result = check_files(ind, roots=[root])
        self.assertEqual(sorted(f.grade for f in result.findings), ["file-match", "name-lead"])

    def test_planted_match_makes_report_exit_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = b"planted match for exit code"
            (root / "dropper.bin").write_bytes(payload)
            ind = _indicators(("sha256", hashlib.sha256(payload).hexdigest(), "confirmed"))
            result = check_files(ind, roots=[root])
        report = _report(result)
        self.assertEqual(report.exit_code(), 2)
        self.assertIn("INDICATOR MATCHES FOUND", render_text(report))

    def test_no_match_is_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "harmless.txt").write_bytes(b"hello")
            ind = _indicators(("sha256", "f" * 64, "confirmed"))
            result = check_files(ind, roots=[root])
        self.assertEqual(_report(result).exit_code(), 0)

    def test_quick_mode_skips_hashing_and_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = b"would match"
            (root / "a.bin").write_bytes(payload)
            ind = _indicators(("sha256", hashlib.sha256(payload).hexdigest(), "confirmed"))
            result = check_files(ind, roots=[root], quick=True)
        self.assertTrue(any("--quick" in g for g in result.gaps))
        self.assertEqual(result.findings, [])

    def test_unreadable_files_are_named_in_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "locked.bin").write_bytes(b"x")
            ind = _indicators(("sha256", "f" * 64, "confirmed"))
            real_hash = __import__("scanner.checks_files", fromlist=["x"]).sha256_file

            def boom(path):
                if path.name == "locked.bin":
                    raise PermissionError("locked")
                return real_hash(path)

            with mock.patch("scanner.checks_files.sha256_file", side_effect=boom):
                result = check_files(ind, roots=[root])
        self.assertTrue(any("locked.bin" in g for g in result.gaps))


class PersistenceTests(unittest.TestCase):
    def test_command_basename(self):
        self.assertEqual(command_basename('"C:\\Users\\x\\Tracker-Helper.exe" /s'), "tracker-helper.exe")
        self.assertEqual(command_basename("/opt/app/tracker-helper --daemon"), "tracker-helper")
        self.assertIsNone(command_basename("   "))

    def test_linux_autostart_and_systemd(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            autostart = home / ".config" / "autostart"
            autostart.mkdir(parents=True)
            (autostart / "helper.desktop").write_text("[Desktop Entry]\nExec=/home/u/bin/tracker-helper --x\n")
            units = home / ".config" / "systemd" / "user"
            units.mkdir(parents=True)
            (units / "svc.service").write_text("[Service]\nExecStart=-/opt/tracker-helper\n")
            ind = _indicators(("filename", "tracker-helper", "confirmed"))
            result = check_persistence(ind, home=home, platform="linux")
        self.assertEqual(len(result.findings), 2)
        self.assertTrue(all(f.grade == "autostart" for f in result.findings))

    def test_windows_run_keys_with_fake_registry(self):
        # The fake reader stands in for winreg, so this runs on any OS.
        def fake_reader(subkey):
            if subkey == WINDOWS_RUN_KEYS[0]:
                return [("Updater", r'"C:\Users\u\AppData\Roaming\tracker-helper.exe" /silent')]
            return [("Benign", r"C:\Program Files\App\app.exe")]

        ind = _indicators(("filename", "tracker-helper.exe", "confirmed"))
        result = check_persistence(
            ind, platform="win32", win_reader=fake_reader, hklm_reader=lambda k: [],
            services_reader=lambda: [], tasks_dir=Path("/nonexistent-tasks"), startup_dirs=[],
        )
        self.assertEqual(len(result.findings), 1)
        self.assertIn("HKCU", result.findings[0].location)
        self.assertEqual(result.examined, 2)

    def test_windows_run_entries_ignores_non_string_values(self):
        entries = windows_run_entries(reader=lambda sub: [("bad", "x")] if sub == WINDOWS_RUN_KEYS[1] else [])
        self.assertEqual(len(entries), 1)

    def test_launchd_plist_parsed_and_broken_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            agents = Path(tmp)
            with (agents / "com.x.plist").open("wb") as fh:
                plistlib.dump({"ProgramArguments": ["/Library/tracker-helper", "-q"]}, fh)
            (agents / "broken.plist").write_bytes(b"not a plist")
            entries, problems = launchd_entries([agents])
        self.assertEqual(entries[0][1], "/Library/tracker-helper")
        self.assertTrue(any("broken.plist" in p for p in problems))


class HostsAndDnsTests(unittest.TestCase):
    def test_sink_is_info_real_address_is_medium(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hosts"
            path.write_text(
                "0.0.0.0 tracker.example.invalid\n"
                "198.51.100.9 api.tracker.example.invalid  # comment\n"
            )
            result = check_hosts(IndicatorSet(load_indicators(SAMPLE)), path=path)
        self.assertEqual({f.grade for f in result.findings}, {"hosts-sink", "hosts-config"})
        self.assertEqual(_report(result).exit_code(), 2)  # hosts-config is actionable

    def test_missing_hosts_file_is_error_status(self):
        result = check_hosts(IndicatorSet([]), path=Path("/no/such/hosts/file"))
        self.assertEqual(result.status, "error")

    def test_parse_hosts_ignores_comments_and_blank_lines(self):
        self.assertEqual(list(parse_hosts("# header\n\n127.0.0.1 localhost\n")), [("127.0.0.1", "localhost")])

    def test_dns_cache_skipped_off_windows(self):
        self.assertEqual(check_dns_cache(IndicatorSet([]), platform="linux").status, "skipped")

    def test_dns_cache_parses_injected_output(self):
        class Proc:
            stdout = (
                b"Windows IP Configuration\r\n\r\n    Record Name . . . . . : tracker.example.invalid\r\n"
                b"    Record Type . . . . . : 1\r\n"
            )

        result = check_dns_cache(
            IndicatorSet(load_indicators(SAMPLE)),
            platform="win32",
            run=lambda *a, **k: Proc(),
        )
        self.assertEqual([f.grade for f in result.findings], ["dns-cache"])

    def test_dns_cache_survives_oem_codepage_bytes(self):
        class Proc:
            # 0x81 is not valid UTF-8 on its own; OEM code pages use it for accented letters.
            stdout = b"Nom de l'h\x81te\r\n    Record Name . . . . . : tracker.example.invalid\r\n"

        result = check_dns_cache(IndicatorSet(load_indicators(SAMPLE)), platform="win32", run=lambda *a, **k: Proc())
        self.assertEqual(len(result.findings), 1)

    def test_decode_console_falls_back(self):
        self.assertEqual(decode_console("café".encode("utf-8")), "café")
        self.assertIsInstance(decode_console(b"\xff\xfe"), str)

    def test_dns_cache_subprocess_failure_is_error(self):
        def failing(*a, **k):
            raise OSError("no ipconfig")

        self.assertEqual(check_dns_cache(IndicatorSet([]), platform="win32", run=failing).status, "error")


class ReportTests(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(defang("evil.example", "domain"), "evil[.]example")
        self.assertEqual(defang("198.51.100.23", "ip"), "198[.]51[.]100[.]23")

    def test_clean_run_is_not_called_clean_and_lists_gaps(self):
        text = render_text(_report(CheckResult("browser", gaps=["no profiles"])))
        self.assertIn("NOT a clean bill of health", text)
        self.assertIn("no profiles", text)

    def test_json_is_serialisable_and_has_verdict(self):
        data = json.loads(json.dumps(_report(CheckResult("files")).to_dict()))
        self.assertEqual(data["exit_code"], 0)
        self.assertIn("verdict", data)


class CliTests(unittest.TestCase):
    def test_bad_indicator_file_returns_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.csv"
            bad.write_text("kind,value,tier,confidence,source\nurl,x,confirmed,high,t\n")
            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                self.assertEqual(main(["--ioc", str(bad)]), 1)
            self.assertIn("unknown kind", err.getvalue())

    def test_quick_scan_writes_json_and_returns_valid_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "report.json"
            with redirect_stdout(io.StringIO()):
                code = main(["--ioc", str(SAMPLE), "--quick", "--json", str(out_path)])
            self.assertIn(code, (0, 2))
            data = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(data["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()
