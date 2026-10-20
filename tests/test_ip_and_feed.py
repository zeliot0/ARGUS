"""IP-indicator matching, the connections check, and the shipped indicator feed."""
import csv
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scanner.checks_browser import check_browsers
from scanner.checks_connections import check_connections, parse_connection_ips
from scanner.checks_network import check_dns_cache, check_hosts, endpoints_from_ipconfig
from scanner.ioc import Indicator, IndicatorSet, load_indicators
from scanner.menu import CHECK_NAMES
from scanner.runner import ScanReport, run_scan

ROOT = Path(__file__).resolve().parent.parent
FEED = ROOT / "iocs" / "adfection.csv"
UNVERIFIED = ROOT / "iocs" / "unverified-candidates.csv"


def _ind(*rows):
    return IndicatorSet(Indicator(k, v, t, "high", "test") for k, v, t in rows)


class Proc:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout, self.returncode = stdout, returncode


WINDOWS_NETSTAT = (
    b"Active Connections\r\n\r\n  Proto  Local Address          Foreign Address        State\r\n"
    b"  TCP    192.168.1.10:51234     203.0.113.9:443        ESTABLISHED\r\n"
    b"  TCP    192.168.1.10:51235     203.0.113.99:443       ESTABLISHED\r\n"
    b"  TCP    192.168.1.10:51236     1203.0.113.9:443       TIME_WAIT\r\n"
    b"  TCP    [::1]:5000             [::1]:51000            ESTABLISHED\r\n"
)
LINUX_SS = b"State Recv-Q Send-Q Local Address:Port Peer Address:Port\nESTAB 0 0 10.0.0.5:44000 203.0.113.9:443\n"


class EndpointTests(unittest.TestCase):
    def test_find_endpoint_ip_and_domain(self):
        ind = _ind(("ip", "203.0.113.9", "lead"), ("domain", "evil.example", "confirmed"))
        self.assertEqual(ind.find_endpoint("203.0.113.9").kind, "ip")
        self.assertEqual(ind.find_endpoint("[203.0.113.9]").kind, "ip")
        self.assertEqual(ind.find_endpoint("a.evil.example").kind, "domain")
        self.assertIsNone(ind.find_endpoint("203.0.113.90"))
        self.assertIsNone(ind.find_endpoint("notevil.example"))

    def test_browser_history_with_ip_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / ".config" / "google-chrome" / "Default"
            profile.mkdir(parents=True)
            conn = sqlite3.connect(profile / "History")
            conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, last_visit_time INTEGER)")
            conn.execute("INSERT INTO urls (url, last_visit_time) VALUES ('http://203.0.113.9:8080/x', 13300000000000000)")
            conn.commit()
            conn.close()
            result = check_browsers(_ind(("ip", "203.0.113.9", "lead")), home=Path(tmp), platform="linux")
        self.assertEqual([f.grade for f in result.findings], ["visit"])
        self.assertEqual(result.findings[0].severity, "low")  # medium, one lower for a lead

    def test_hosts_file_mapping_to_indicator_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            hosts = Path(tmp) / "hosts"
            hosts.write_text("203.0.113.9 updates.somewhere.test\n127.0.0.1 localhost\n")
            result = check_hosts(_ind(("ip", "203.0.113.9", "lead")), path=hosts)
        self.assertEqual([f.grade for f in result.findings], ["hosts-config"])

    def test_dns_answers_are_checked_via_powershell_and_ipconfig(self):
        ind = _ind(("ip", "198.51.100.23", "lead"))
        ps = check_dns_cache(ind, platform="win32", run=lambda c, **k: Proc(b"harmless.test\r\n198.51.100.23\r\n"))
        self.assertEqual([f.grade for f in ps.findings], ["dns-cache"])
        text = ("    x.test\n    ------\n    Nom . . . . : x.test\n    Type . . . . : 1\n"
                "    Enregistrement A . . . . : 198.51.100.23\n")
        self.assertIn("198.51.100.23", endpoints_from_ipconfig(text))
        self.assertNotIn("1", endpoints_from_ipconfig(text))


class ConnectionsTests(unittest.TestCase):
    def test_parse_ignores_ports_and_lookalikes(self):
        ips = parse_connection_ips(WINDOWS_NETSTAT.decode())
        self.assertIn("203.0.113.9", ips)
        self.assertIn("203.0.113.99", ips)
        self.assertNotIn("1203.0.113.9", ips)
        self.assertEqual(len(ips), len(set(ips)))

    def test_only_exact_ip_matches(self):
        result = check_connections(_ind(("ip", "203.0.113.9", "lead")), platform="win32", run=lambda c, **k: Proc(WINDOWS_NETSTAT))
        self.assertEqual([f.grade for f in result.findings], ["connection"])
        self.assertIn("203.0.113.9", result.findings[0].detail)
        self.assertEqual(result.findings[0].severity, "medium")  # high, one lower for a lead

    def test_linux_uses_ss_first_then_netstat(self):
        calls = []

        def run(cmd, **k):
            calls.append(cmd[0])
            if cmd[0] == "ss":
                raise OSError("no ss")
            return Proc(WINDOWS_NETSTAT)

        result = check_connections(_ind(("ip", "203.0.113.9", "lead")), platform="linux", run=run)
        self.assertEqual(calls, ["ss", "netstat"])
        self.assertEqual(len(result.findings), 1)
        result = check_connections(_ind(("ip", "203.0.113.9", "lead")), platform="linux", run=lambda c, **k: Proc(LINUX_SS))
        self.assertEqual(len(result.findings), 1)

    def test_no_tool_available_is_an_error_not_clean(self):
        def run(cmd, **k):
            raise OSError("missing")

        result = check_connections(_ind(("ip", "203.0.113.9", "lead")), platform="linux", run=run)
        self.assertEqual(result.status, "error")

    def test_runner_knows_the_check(self):
        self.assertIn("connections", CHECK_NAMES)
        report = run_scan(_ind(("ip", "203.0.113.9", "lead")), only=["connections"])
        self.assertEqual([r.name for r in report.results], ["connections"])


class ShippedFeedTests(unittest.TestCase):
    def setUp(self):
        self.rows = [r for r in csv.reader(l for l in FEED.read_text(encoding="utf-8").splitlines() if not l.startswith("#"))]

    def test_feed_loads_and_every_row_has_a_source(self):
        inds = load_indicators(FEED)
        self.assertGreaterEqual(len(inds), 230)
        self.assertTrue(all(i.source for i in inds))
        self.assertFalse(any(i.source.lower().startswith("placeholder") for i in inds))

    def test_feed_has_no_duplicates(self):
        keys = [(r[0], r[1]) for r in self.rows[1:]]
        self.assertEqual(len(keys), len(set(keys)))

    def test_known_indicators_are_present_with_the_right_tier(self):
        s = IndicatorSet(load_indicators(FEED))
        self.assertEqual(s.get("domain", "fearevolve.com").tier, "confirmed")
        self.assertEqual(s.get("domain", "keyadapter.com").tier, "confirmed")
        self.assertEqual(s.get("sha256", "255869de85e2a171993fc5eb8a556d873a1b8966e040f6f55926f2fa2d595cc8").tier, "confirmed")
        self.assertEqual(s.get("domain", "noas.mtrtb.com").tier, "lead")
        self.assertEqual(s.get("ip", "217.69.6.58").tier, "lead")

    def test_unverified_rows_are_not_in_the_feed(self):
        feed = IndicatorSet(load_indicators(FEED))
        with UNVERIFIED.open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(l for l in fh if not l.startswith("#")))
        self.assertGreater(len(rows), 100)
        self.assertTrue(all(r["reason"] for r in rows))
        for r in rows:
            self.assertIsNone(feed.get(r["kind"], r["value"]), r["value"])

    def test_the_three_mislabelled_hosts_are_not_trusted(self):
        feed = IndicatorSet(load_indicators(FEED))
        self.assertIsNone(feed.get("ip", "52.174.65.77"))
        self.assertIsNone(feed.get("domain", "bd-mainserver.herokuapp.com"))

    def test_real_feed_matches_a_planted_hosts_entry_end_to_end(self):
        feed = IndicatorSet(load_indicators(FEED))
        with tempfile.TemporaryDirectory() as tmp:
            hosts = Path(tmp) / "hosts"
            hosts.write_text("203.0.113.5 fearevolve.com\n")
            result = check_hosts(feed, path=hosts)
        report = ScanReport(started="t", platform="t", indicator_count=len(feed), results=[result])
        self.assertEqual(report.exit_code(), 2)


if __name__ == "__main__":
    unittest.main()
