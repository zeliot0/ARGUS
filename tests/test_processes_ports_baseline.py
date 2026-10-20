"""Running processes, listening ports, and the baseline diff."""
import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scanner import baseline
from scanner.checks_persistence import check_persistence
from scanner.checks_ports import check_ports, parse_lsof_listeners, parse_ss_listeners, parse_windows_listeners
from scanner.checks_processes import (
    Proc, check_processes, list_processes, processes_from_proc_fs,
)
from scanner.evidence import CheckResult
from scanner.ioc import Indicator, IndicatorSet
from scanner.runner import ScanReport, run_scan


def inds(kind, *values, tier="confirmed"):
    return IndicatorSet(Indicator(kind, v, tier, "high", "t") for v in values)


class FakeCompleted:
    def __init__(self, stdout=b"", returncode=0, stderr=b""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


class ProcFsTests(unittest.TestCase):
    def _make(self, root: Path, pid: str, exe: Path, comm: str = ""):
        d = root / pid
        d.mkdir()
        (d / "exe").symlink_to(exe)
        if comm:
            (d / "comm").write_text(comm + "\n")

    def test_reads_exe_symlink_and_comm(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "bin" / "evil"
            target.parent.mkdir()
            target.write_bytes(b"x")
            self._make(root, "123", target, "evil")
            self._make(root, "notapid", target)  # ignored: not numeric
            procs = processes_from_proc_fs(root)
        self.assertEqual(procs, [Proc("123", "evil", str(target))])

    def test_missing_exe_still_yields_name_from_comm(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "5"
            d.mkdir()
            (d / "comm").write_text("ghost\n")
            self.assertEqual(processes_from_proc_fs(root), [Proc("5", "ghost", None)])


class WindowsProcessParsingTests(unittest.TestCase):
    def test_parses_json_array_and_single_object(self):
        from scanner.checks_processes import _parse_windows_json

        arr = '[{"Id":1,"ProcessName":"svchost","Path":"C:\\\\Windows\\\\svchost.exe"},{"Id":2,"ProcessName":"x","Path":null}]'
        self.assertEqual(
            _parse_windows_json(arr),
            [Proc("1", "svchost", r"C:\Windows\svchost.exe"), Proc("2", "x", None)],
        )
        self.assertEqual(_parse_windows_json('{"Id":1,"ProcessName":"a","Path":null}'), [Proc("1", "a", None)])


class CheckProcessesTests(unittest.TestCase):
    def test_hash_match_on_disk_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "evil.exe"
            payload = b"not malware, a test payload"
            exe.write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            root = Path(tmp) / "proc"
            root.mkdir()
            d = root / "9"
            d.mkdir()
            (d / "exe").symlink_to(exe)
            (d / "comm").write_text("evil.exe\n")
            result = check_processes(inds("sha256", digest), platform="linux", proc_dir=root)
        self.assertEqual([f.grade for f in result.findings], ["process-match"])

    def test_name_only_when_no_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "proc"
            root.mkdir()
            d = root / "9"
            d.mkdir()
            (d / "comm").write_text("evil-tool\n")
            result = check_processes(inds("filename", "evil-tool"), platform="linux", proc_dir=root)
        self.assertEqual([f.grade for f in result.findings], ["process-name-lead"])
        self.assertTrue(any("no accessible executable path" in g for g in result.gaps))

    def test_quick_skips_hashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "evil.exe"
            exe.write_bytes(b"x" * 10)
            digest = hashlib.sha256(b"x" * 10).hexdigest()
            root = Path(tmp) / "proc"
            root.mkdir()
            d = root / "9"
            d.mkdir()
            (d / "exe").symlink_to(exe)
            result = check_processes(inds("sha256", digest), platform="linux", proc_dir=root, quick=True)
        self.assertEqual(result.findings, [])
        self.assertTrue(any("--quick" in g for g in result.gaps))

    def test_windows_process_list_via_fake_powershell(self):
        proc = FakeCompleted(stdout=b'[{"Id":1,"ProcessName":"evil","Path":null}]')
        result = check_processes(inds("filename", "evil"), platform="win32", run=lambda *a, **k: proc, quick=True)
        self.assertEqual(len(result.findings), 1)

    def test_macos_ps_fallback(self):
        proc = FakeCompleted(stdout=b"123 /usr/libexec/evil\n")
        result = check_processes(inds("filename", "evil"), platform="darwin", run=lambda *a, **k: proc, quick=True)
        self.assertEqual(len(result.findings), 1)

    def test_no_processes_is_a_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = check_processes(inds("filename", "x"), platform="linux", proc_dir=Path(tmp) / "nope")
        self.assertTrue(any("no process" in g or "no running" in g for g in result.gaps))


WINDOWS_NETSTAT = (
    "\n  Proto  Local Address          Foreign Address        State           PID\n"
    "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       900\n"
    "  TCP    127.0.0.1:5040         0.0.0.0:0              LISTENING       7244\n"
)
SS_OUTPUT = (
    'LISTEN 0 128 0.0.0.0:22  0.0.0.0:* users:(("sshd",pid=1200,fd=3))\n'
    'LISTEN 0 128 127.0.0.1:631 0.0.0.0:* users:(("evil-tool",pid=999,fd=5))\n'
)
LSOF_OUTPUT = (
    "COMMAND   PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
    "sshd      123 root 3u IPv6 0x1 0t0 TCP *:22 (LISTEN)\n"
    "evil-tool 456 sal  3u IPv4 0x2 0t0 TCP *:8080 (LISTEN)\n"
)


class PortsParsingTests(unittest.TestCase):
    def test_windows(self):
        out = parse_windows_listeners(WINDOWS_NETSTAT, {"7244": "evil-tool.exe"})
        self.assertEqual(out[1].process, "evil-tool.exe")

    def test_ss_and_lsof(self):
        self.assertEqual(parse_ss_listeners(SS_OUTPUT)[1].process, "evil-tool")
        self.assertEqual(parse_lsof_listeners(LSOF_OUTPUT)[1].process, "evil-tool")


class CheckPortsTests(unittest.TestCase):
    def test_linux_flags_matching_listener_and_fills_inventory(self):
        proc = FakeCompleted(stdout=SS_OUTPUT.encode())
        result = check_ports(inds("filename", "evil-tool"), platform="linux", run=lambda *a, **k: proc)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].grade, "listener-lead")
        self.assertEqual(len(result.inventory), 2)

    def test_windows_needs_pid_name_map_from_caller(self):
        # check_ports on win32 alone has no process-name column; pid-name joining is a caller concern.
        proc = FakeCompleted(stdout=WINDOWS_NETSTAT.encode())
        result = check_ports(inds("filename", "evil-tool.exe"), platform="win32", run=lambda *a, **k: proc)
        self.assertEqual(result.findings, [])  # no names resolved without a pid map
        self.assertEqual(result.examined, 2)

    def test_no_tool_available_is_an_error(self):
        def boom(*a, **k):
            raise OSError("missing")

        result = check_ports(inds("filename", "x"), platform="linux", run=boom)
        self.assertEqual(result.status, "error")

    def test_unnamed_listener_is_a_gap(self):
        proc = FakeCompleted(stdout=b"LISTEN 0 1 0.0.0.0:9999 0.0.0.0:* \n")
        result = check_ports(inds("filename", "x"), platform="linux", run=lambda *a, **k: proc)
        self.assertEqual(result.findings, [])


def _report(checks):
    report = ScanReport(started="2026-01-01T00:00:00+00:00", platform="p", indicator_count=0)
    for name, inventory in checks.items():
        result = CheckResult(name)
        result.inventory = list(inventory)
        report.results.append(result)
    return report


class BaselineTests(unittest.TestCase):
    def test_new_item_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            old = _report({"persistence": [("HKCU\\Run\\A", "a.exe")]})
            self.assertIsNone(baseline.set_baseline(d, old))
            new = _report({"persistence": [("HKCU\\Run\\A", "a.exe"), ("HKCU\\Run\\B", "b.exe")]})
            diff = baseline.compare(baseline.load(d), new)
        self.assertEqual(diff.new, [("persistence", "HKCU\\Run\\B", "b.exe")])

    def test_check_that_did_not_run_is_reported_not_covered(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            baseline.set_baseline(d, _report({"ports": [("PID 1", "0.0.0.0:80")]}))
            result = CheckResult("ports", status="skipped")
            report = ScanReport(started="t", platform="p", indicator_count=0, results=[result])
            diff = baseline.compare(baseline.load(d), report)
        self.assertEqual(diff.not_covered, ["ports"])
        self.assertEqual(diff.new, [])

    def test_no_baseline_yet(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(baseline.exists(Path(tmp)))
            self.assertIsNone(baseline.load(Path(tmp)))

    def test_corrupt_baseline_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / baseline.CONFIG_NAME).write_text("not json")
            self.assertIsNone(baseline.load(d))

    def test_save_failure_returns_a_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "blocker"
            blocker.write_text("x")
            self.assertIsNotNone(baseline.set_baseline(blocker, _report({})))


class RealRunnerWiringTests(unittest.TestCase):
    def test_processes_and_ports_run_in_a_full_scan(self):
        report = run_scan(inds("filename", "nonexistent-xyz"), quick=True)
        names = {r.name for r in report.results}
        self.assertIn("processes", names)
        self.assertIn("ports", names)


if __name__ == "__main__":
    unittest.main()
