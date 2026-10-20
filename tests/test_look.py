"""The visual layer: Unicode drawing, ASCII fallback, spinner, width discipline."""
import io
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scanner.ui import ASCII_GLYPHS, BANNER_UNICODE, UNICODE_GLYPHS, Console, Spinner, unicode_supported, visible_len
from scanner.menu import App
from tests.test_persistence_and_history import report_with, scripted


class Utf8Out(io.StringIO):
    encoding = "utf-8"


def con(unicode=True, color=True, width=80, read=None):
    out = Utf8Out()
    return Console(out=out, read=read or (lambda p: ""), color=color, width=width, clear=False, unicode=unicode), out


class GlyphTests(unittest.TestCase):
    def test_detection(self):
        self.assertTrue(unicode_supported(Utf8Out()))
        self.assertFalse(unicode_supported(io.StringIO()))
        class Cp(io.StringIO):
            encoding = "cp1252"

        cp = Cp()
        self.assertFalse(unicode_supported(cp))
        with mock.patch.dict("os.environ", {"ARGUS_ASCII": "1"}):
            self.assertFalse(unicode_supported(Utf8Out()))

    def test_both_sets_have_the_same_keys(self):
        self.assertEqual(set(ASCII_GLYPHS), set(UNICODE_GLYPHS))

    def test_ascii_mode_emits_only_ascii(self):
        c, out = con(unicode=False, color=False)
        c.banner(); c.rule(); c.info("a"); c.good("b"); c.warn("c"); c.bad("d")
        c.box(["hello"]); c.panel("T", ["row"]); c.say(c.bar(3, 10, 10))
        out.getvalue().encode("ascii")

    def test_banner_lines_have_equal_width(self):
        self.assertEqual(len({len(l) for l in BANNER_UNICODE}), 1)


class DrawingTests(unittest.TestCase):
    def test_box_panel_and_rows_fit_the_width(self):
        c, out = con(width=60)
        c.box(["a long line " * 8, "", "short"], "green")
        c.panel("TITLE", [c.paint("coloured row", "red", "bold"), "plain"], "c39")
        for line in out.getvalue().splitlines():
            self.assertEqual(visible_len(line), 60, line)

    def test_256_colour_codes(self):
        c, _ = con()
        self.assertIn("\x1b[38;5;51m", c.paint("x", "c51"))

    def test_bar_uses_blocks(self):
        c, _ = con(color=False)
        self.assertEqual(c.bar(5, 10, 10), "█" * 5 + "░" * 5)


class ScreenTests(unittest.TestCase):
    def app(self, inputs, unicode=True):
        feeds = Path(tempfile.mkdtemp())
        (feeds / "alpha.csv").write_text("kind,value,tier,confidence,source\ndomain,a.example,lead,high,t\n")
        out = Utf8Out()
        console = Console(out=out, read=scripted(inputs), color=True, width=80, clear=False, unicode=unicode)
        return App(console, feeds_dir=feeds, reports_dir=Path(tempfile.mkdtemp())), out

    def test_unicode_menu_and_header_fit_and_show_icons(self):
        app, out = self.app(["0"])
        app.run()
        text = out.getvalue()
        self.assertIn("╭", text)
        self.assertIn("[1]", text)
        self.assertIn("█", text)
        for line in text.splitlines():
            self.assertLessEqual(visible_len(line), 80, line)

    def test_report_screen_unicode_has_icons_and_cards(self):
        app, out = self.app(["0"])
        app.run()
        out.truncate(0)
        app.show_report(report_with(("hosts", "hosts-config", "a.example", "h")))
        text = out.getvalue()
        for mark in ("✖", "✔", "▌", "COULD NOT CHECK"):
            self.assertIn(mark, text)

    def test_settings_toggle_switches_to_ascii(self):
        app, out = self.app(["6", "5", "0", "0"])
        app.run()
        self.assertFalse(app.c.unicode)
        self.assertIn("Fancy symbols are now off", out.getvalue())


class SpinnerTests(unittest.TestCase):
    def test_noninteractive_spinner_is_silent(self):
        c, out = con()
        sp = Spinner(c)
        sp.start("x"); sp.update("y"); sp.stop()
        self.assertEqual(out.getvalue(), "")

    def test_interactive_spinner_draws_and_cleans_up(self):
        c, out = con(width=40)
        with mock.patch.object(Console, "interactive", True):
            sp = Spinner(c)
            sp.start("files 1 examined")
            import time; time.sleep(0.25)
            sp.update("files 2 examined")
            sp.stop()
        text = out.getvalue()
        self.assertIn("files 1 examined", text)
        self.assertTrue(text.endswith("\r"))
        self.assertTrue(re.search(r"[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]", text))


if __name__ == "__main__":
    unittest.main()


class ThreatTests(unittest.TestCase):
    def test_levels(self):
        from scanner.menu import threat_level
        self.assertEqual(threat_level(report_with())[0], "NO KNOWN INDICATORS")
        self.assertEqual(threat_level(report_with(("files", "name-lead", "a.example", "f")))[0], "GUARDED")
        self.assertEqual(threat_level(report_with(("hosts", "hosts-config", "a.example", "h")))[0], "ELEVATED")
        self.assertEqual(threat_level(report_with(("files", "file-match", "a.example", "f")))[0], "CRITICAL")
        self.assertEqual(threat_level(report_with(("hosts", "hosts-sink", "a.example", "h")))[0], "NO KNOWN INDICATORS")

    def test_gauge_and_status_strip_render_in_both_modes(self):
        for uni in (True, False):
            feeds = Path(tempfile.mkdtemp())
            (feeds / "alpha.csv").write_text("kind,value,tier,confidence,source\ndomain,a.example,lead,high,t\n")
            out = Utf8Out()
            console = Console(out=out, read=scripted(["0"]), color=False, width=80, clear=False, unicode=uni)
            app = App(console, feeds_dir=feeds, reports_dir=Path(tempfile.mkdtemp()))
            app.run()
            app.show_report(report_with(("files", "file-match", "a.example", "f")))
            text = out.getvalue()
            self.assertIn("THREAT LEVEL", text)
            self.assertIn("CRITICAL", text)
            self.assertIn("NETWORK LOCKED", text)
            if not uni:
                text.encode("ascii")

    def test_never_claims_safe(self):
        from scanner.menu import threat_level
        self.assertNotIn("SAFE", threat_level(report_with())[0])

    def test_intro_is_skipped_when_not_interactive(self):
        app = ScreenTests().app(["0"])[0]
        out_before = app.c.out.getvalue()
        app.intro()
        self.assertEqual(app.c.out.getvalue(), out_before)

    def test_typed_prints_instantly_when_piped(self):
        c, out = con(color=False)
        c.typed("hello")
        self.assertEqual(out.getvalue(), "hello\n")


class DesignUpgradeTests(unittest.TestCase):
    def test_header_embeds_title_in_a_rule_and_fits_width(self):
        c, out = con(width=50)
        c.header("SEVERITY")
        line = out.getvalue().rstrip("\n")
        self.assertIn("SEVERITY", line)
        self.assertEqual(visible_len(line), 50)

    def test_header_ascii_mode_is_plain_ascii(self):
        c, out = con(unicode=False, color=False, width=40)
        c.header("CHECKS")
        out.getvalue().encode("ascii")
        self.assertIn("-- CHECKS", out.getvalue())

    def test_badge_uses_background_colour_when_colour_is_on(self):
        c, _ = con(color=True)
        self.assertIn("48;5;196", c.badge("HIGH", "c196"))

    def test_badge_falls_back_to_brackets_without_colour(self):
        c, _ = con(color=False)
        self.assertEqual(c.badge("HIGH", "c196"), "[HIGH]")

    def test_sparkline_scales_to_the_peak_and_has_one_glyph_per_value(self):
        c, _ = con(color=False)
        line = c.sparkline([0, 1, 5, 2])
        self.assertEqual(len(line), 4)
        for ch in line:
            self.assertIn(ch, "▁▂▄▆█")
        self.assertEqual(c.sparkline([0, 0, 0]), "▁" * 3)

    def test_sparkline_ascii_fallback(self):
        c, _ = con(unicode=False, color=False)
        line = c.sparkline([0, 5])
        for ch in line:
            self.assertIn(ch, "_.-=#")
        self.assertNotIn(" ", line)  # a zero value must still be visible, not blank

    def test_double_box_uses_double_line_glyphs(self):
        c, out = con(width=40)
        c.box(["x"], "red", double=True)
        self.assertIn("╔", out.getvalue())
        self.assertIn("╚", out.getvalue())

    def test_double_box_ascii_still_plain(self):
        c, out = con(unicode=False, color=False, width=40)
        c.box(["x"], double=True)
        out.getvalue().encode("ascii")


class TrendTests(unittest.TestCase):
    def test_trend_line_appears_with_history_and_not_without(self):
        from scanner import history
        from scanner.menu import App

        from tests.test_persistence_and_history import report_with
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            out = Utf8Out()
            console = Console(out=out, read=lambda p: "0", color=False, width=80, clear=False, unicode=True)
            app = App(console, reports_dir=reports)
            app.run()
            self.assertNotIn("Trend", out.getvalue())

            out.truncate(0); out.seek(0)
            history.save(app.history_dir, report_with())
            history.save(app.history_dir, report_with(("hosts", "hosts-config", "a.example", "h")))
            app2 = App(Console(out=out, read=lambda p: "0", color=False, width=80, clear=False, unicode=True), reports_dir=reports)
            app2.run()
            self.assertIn("Trend", out.getvalue())


class SigilTests(unittest.TestCase):
    def test_sigil_renders_in_both_modes_and_fits_width(self):
        for uni in (True, False):
            c, out = con(unicode=uni, color=False, width=60)
            c.sigil()
            for line in out.getvalue().splitlines():
                self.assertLessEqual(visible_len(line), 60)
            if not uni:
                out.getvalue().encode("ascii")

    def test_sigil_has_no_literal_mr_robot_or_fsociety_reference(self):
        from scanner.ui import EYE_SIGIL_ASCII, EYE_SIGIL_UNICODE, MANIFESTO_LINES

        blob = " ".join(EYE_SIGIL_ASCII + EYE_SIGIL_UNICODE + MANIFESTO_LINES).lower()
        for banned in ("fsociety", "mr robot", "mr. robot", "elliot", "hello friend", "hello, friend"):
            self.assertNotIn(banned, blob)

    def test_about_and_intro_show_the_sigil(self):
        import tempfile
        from scanner.menu import App
        from tests.test_persistence_and_history import scripted

        feeds = Path(tempfile.mkdtemp())
        out = Utf8Out()
        console = Console(out=out, read=scripted(["7", "", "0"]), color=False, width=80, clear=False, unicode=True)
        app = App(console, reports_dir=Path(tempfile.mkdtemp()))
        app.run()
        self.assertIn("never sleeps", out.getvalue())

    def test_intro_sigil_is_skipped_when_not_interactive(self):
        import tempfile
        from scanner.menu import App
        from tests.test_persistence_and_history import scripted

        out = Utf8Out()
        console = Console(out=out, read=scripted(["0"]), color=False, width=80, clear=False, unicode=True)
        app = App(console, reports_dir=Path(tempfile.mkdtemp()))
        app.run()
        self.assertNotIn("never sleeps", out.getvalue())
