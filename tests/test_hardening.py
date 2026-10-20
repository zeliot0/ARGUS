"""Regression tests for defects found on a real Windows run."""
import tempfile
import unittest
from pathlib import Path

from scanner.checks_files import check_files
from scanner.checks_network import check_dns_cache, names_from_ipconfig, names_from_powershell
from scanner.ioc import Indicator, IndicatorSet


def _ind(*rows):
    return IndicatorSet(Indicator(k, v, t, "high", "test") for k, v, t in rows)


class Proc:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout = stdout
        self.returncode = returncode


# French-style output: no "Record Name" anywhere, accented bytes in the OEM code page.
FRENCH_IPCONFIG = (
    b"Configuration IP de Windows\r\n\r\n"
    b"    tracker.example.invalid\r\n"
    b"    ----------------------------------------\r\n"
    b"    Nom de l'enregistrement . . . . . : tracker.example.invalid\r\n"
    b"    Type d'enregistrement . . . . . . : 1\r\n"
    b"    Dur\x82e de vie . . . . . . . . . . : 300\r\n"
    b"    Section . . . . . . . . . . . . . : R\x82ponse\r\n"
    b"    Enregistrement A (h\x93te) . . . . . : 198.51.100.23\r\n\r\n"
    b"    other.example\r\n"
    b"    ----------------------------------------\r\n"
    b"    Nom de l'enregistrement . . . . . : other.example\r\n"
    b"    Type d'enregistrement . . . . . . : 1\r\n"
)


class PerFolderBudgetTests(unittest.TestCase):
    def test_big_folder_does_not_starve_the_next_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            big, small = Path(tmp) / "big", Path(tmp) / "small"
            big.mkdir()
            small.mkdir()
            for i in range(10):
                (big / f"f{i}.txt").write_bytes(b"x")
            (small / "tracker-helper").write_bytes(b"y")
            ind = _ind(("filename", "tracker-helper", "confirmed"))
            result = check_files(ind, roots=[big, small], quick=True, max_files=3)
        self.assertEqual(len(result.findings), 1, "the second folder must still be scanned")
        self.assertEqual(result.examined, 4)

    def test_truncated_folder_is_named_in_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            big = Path(tmp) / "big"
            big.mkdir()
            for i in range(5):
                (big / f"f{i}.txt").write_bytes(b"x")
            result = check_files(_ind(("filename", "zzz", "confirmed")), roots=[big], quick=True, max_files=2)
        self.assertTrue(any(str(big) in g and "stopped at 2" in g for g in result.gaps))

    def test_folder_exactly_at_the_limit_is_not_reported_truncated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "r"
            root.mkdir()
            for i in range(3):
                (root / f"f{i}.txt").write_bytes(b"x")
            result = check_files(_ind(("filename", "zzz", "confirmed")), roots=[root], quick=True, max_files=3)
        self.assertFalse(any("stopped at" in g for g in result.gaps))


class LocalisedDnsTests(unittest.TestCase):
    def test_parses_ipconfig_without_english_labels(self):
        text = FRENCH_IPCONFIG.decode("cp850")
        self.assertEqual(names_from_ipconfig(text), ["tracker.example.invalid", "other.example"])

    def test_powershell_lines_filtered_to_names(self):
        text = "tracker.example.invalid\r\nWindows IP Configuration\r\n\r\nlocalhost\r\nother.example\r\n"
        self.assertEqual(names_from_powershell(text), ["tracker.example.invalid", "other.example"])

    def test_falls_back_to_localised_ipconfig_when_powershell_fails(self):
        calls = []

        def run(cmd, **kwargs):
            calls.append(cmd[0])
            return Proc(b"", returncode=1) if cmd[0] == "powershell.exe" else Proc(FRENCH_IPCONFIG)

        ind = _ind(("domain", "tracker.example.invalid", "confirmed"))
        result = check_dns_cache(ind, platform="win32", run=run)
        self.assertEqual([f.grade for f in result.findings], ["dns-cache"])
        self.assertEqual(result.examined, 3)  # two record names plus the IP answer
        self.assertEqual(calls, ["powershell.exe", "ipconfig"])

    def test_powershell_result_used_without_calling_ipconfig(self):
        calls = []

        def run(cmd, **kwargs):
            calls.append(cmd[0])
            return Proc(b"tracker.example.invalid\r\nother.example\r\n")

        ind = _ind(("domain", "tracker.example.invalid", "confirmed"))
        result = check_dns_cache(ind, platform="win32", run=run)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(calls, ["powershell.exe"])

    def test_both_commands_failing_is_an_error_not_a_clean_result(self):
        def run(cmd, **kwargs):
            raise OSError("not found")

        result = check_dns_cache(_ind(("domain", "tracker.example.invalid", "confirmed")), platform="win32", run=run)
        self.assertEqual(result.status, "error")

    def test_empty_cache_is_reported_as_a_gap(self):
        result = check_dns_cache(
            _ind(("domain", "tracker.example.invalid", "confirmed")),
            platform="win32",
            run=lambda cmd, **kw: Proc(b""),
        )
        self.assertEqual(result.status, "ran")
        self.assertTrue(any("no DNS cache records" in g for g in result.gaps))


if __name__ == "__main__":
    unittest.main()


class DnsCacheJsonTests(unittest.TestCase):
    def test_json_array_is_parsed(self):
        from scanner.checks_network import names_from_powershell
        text = '[{"Entry":"tracker.example.invalid","Data":"198.51.100.23"},{"Entry":"ok.example","Data":"1.2.3.4"}]'
        self.assertEqual(
            names_from_powershell(text), ["tracker.example.invalid", "198.51.100.23", "ok.example", "1.2.3.4"]
        )

    def test_single_object_without_array_is_accepted(self):
        from scanner.checks_network import names_from_powershell
        text = '{"Entry":"tracker.example.invalid","Data":"198.51.100.23"}'
        self.assertEqual(names_from_powershell(text), ["tracker.example.invalid", "198.51.100.23"])

    def test_non_json_falls_back_to_line_reading(self):
        from scanner.checks_network import names_from_powershell
        self.assertEqual(names_from_powershell("tracker.example.invalid\n"), ["tracker.example.invalid"])

    def test_dns_cache_reports_why_both_commands_failed(self):
        from scanner.checks_network import check_dns_cache
        from scanner.ioc import IndicatorSet

        class Proc:
            returncode = 1
            stdout = b""
            stderr = b"Get-DnsClientCache : access is denied"

        result = check_dns_cache(IndicatorSet([]), platform="win32", run=lambda *a, **k: Proc())
        self.assertEqual(result.status, "error")
        self.assertIn("access is denied", result.note)

    def test_dns_cache_empty_result_names_the_reason(self):
        from scanner.checks_network import check_dns_cache
        from scanner.ioc import IndicatorSet

        class Proc:
            returncode = 0
            stdout = b"[]"
            stderr = b""

        result = check_dns_cache(IndicatorSet([]), platform="win32", run=lambda *a, **k: Proc())
        self.assertEqual(result.status, "ran")
        self.assertTrue(any("genuinely be empty" in g for g in result.gaps))
