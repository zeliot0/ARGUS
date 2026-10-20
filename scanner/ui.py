"""Terminal helpers: colour, banner, boxes, spinner.

Unicode drawing is used only on a UTF-8 stream; otherwise, or with ARGUS_ASCII=1, this falls
back to plain ASCII.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import textwrap
import threading
import time
from typing import Callable, Optional, Sequence, TextIO

BANNER = [
    r"    _    ____   ____ _   _ ____  ",
    r"   / \  |  _ \ / ___| | | / ___| ",
    r"  / _ \ | |_) | |  _| | | \___ \ ",
    r" / ___ \|  _ <| |_| | |_| |___) |",
    r"/_/   \_\_| \_\\____|\___/|____/ ",
]

BANNER_UNICODE = [
    " █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗",
    "██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝",
    "███████║██████╔╝██║  ███╗██║   ██║███████╗",
    "██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║",
    "██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║",
    "╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝",
]
BANNER_GRADIENT = ("c224", "c217", "c210", "c203", "c196", "c160")  # pale -> blood red

# Argus Panoptes: the hundred-eyed giant who never sleeps.
EYE_SIGIL_UNICODE = [
    "     ╭──────╮     ",
    "   ╭─┤ ◉  ◉ ├─╮   ",
    "  ╱  ╰──────╯  ╲  ",
    " ╱  the machine ╲ ",
    "╱   never sleeps  ╲",
]
EYE_SIGIL_ASCII = [
    "     .------.     ",
    "   .-( o  o )-.   ",
    "  (  '------'  )  ",
    " (  the machine ) ",
    "(   never sleeps  )",
]

MANIFESTO_LINES = [
    "One truth, machine: every autostart entry answers to someone. Tonight, you find out who.",
    "Systems trust what they are told to trust. We check that trust, quietly, and leave no mark.",
    "No alarms. No calls home. Just a long look at every corner you forgot you had.",
    "A hundred checks, one verdict: known, or not yet known. Nothing here is ever called safe.",
    "We do not break in. We already live here. We are only now switching on the light.",
]


ASCII_GLYPHS = {
    "h": "-", "v": "|", "tl": "+", "tr": "+", "bl": "+", "br": "+",
    "full": "#", "empty": "-", "info": "[*]", "ok": "[+]", "warn": "[!]", "bad": "[x]", "dot": "*",
    "bar": "|", "spin": "|/-\\", "seg": "#", "seg_off": "-",
    "spark": "_.-=#", "dtl": "+", "dtr": "+", "dbl": "+", "dbr": "+", "dh": "=", "dv": "#",
}
UNICODE_GLYPHS = {
    "h": "─", "v": "│", "tl": "╭", "tr": "╮", "bl": "╰", "br": "╯",
    "full": "█", "empty": "░", "info": "›", "ok": "✔", "warn": "▲", "bad": "✖", "dot": "●",
    "bar": "▌", "spin": "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏", "seg": "▰", "seg_off": "▱",
    "spark": "▁▂▄▆█", "dtl": "╔", "dtr": "╗", "dbl": "╚", "dbr": "╝", "dh": "═", "dv": "║",
}
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def visible_len(text: str) -> int:
    return len(_ANSI.sub("", text))


def unicode_supported(stream: TextIO) -> bool:
    if os.environ.get("ARGUS_ASCII"):
        return False
    return "utf" in (getattr(stream, "encoding", None) or "").lower()


_CODES = {
    "bold": "1", "dim": "2",
    "red": "31", "green": "32", "yellow": "33", "blue": "34",
    "magenta": "35", "cyan": "36", "white": "37", "grey": "90",
}


def enable_windows_vt() -> bool:
    """Turn on ANSI escape handling in the Windows console. True elsewhere."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def color_supported(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    if not (isatty and isatty()):
        return False
    return enable_windows_vt()


def safe_console() -> None:
    """Never let printing a non-encodable character crash a scan (Windows code pages)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (OSError, ValueError):
                pass


class Console:
    """Output and input in one place, so the menus can be tested with scripted input."""

    def __init__(
        self,
        out: Optional[TextIO] = None,
        read: Optional[Callable[[str], str]] = None,
        color: Optional[bool] = None,
        width: Optional[int] = None,
        clear: Optional[bool] = None,
        unicode: Optional[bool] = None,
    ):
        self.out = out if out is not None else sys.stdout
        self.read = read or input
        self.color = color_supported(self.out) if color is None else color
        self._width = width
        self._can_clear = self.color if clear is None else clear
        self.unicode = unicode_supported(self.out) if unicode is None else unicode

    @property
    def g(self) -> dict:
        return UNICODE_GLYPHS if self.unicode else ASCII_GLYPHS

    @property
    def width(self) -> int:
        if self._width:
            return self._width
        columns = shutil.get_terminal_size((80, 24)).columns
        return max(40, min(columns, 100))

    def paint(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        codes = ";".join(_CODES[s] if s in _CODES else f"38;5;{s[1:]}" for s in styles)
        return f"\x1b[{codes}m{text}\x1b[0m"

    def say(self, text: str = "") -> None:
        self.out.write(text + "\n")
        self.out.flush()

    def info(self, text: str) -> None:
        self.say(f"{self.paint(self.g['info'], 'cyan', 'bold')} {text}")

    def good(self, text: str) -> None:
        self.say(f"{self.paint(self.g['ok'], 'green', 'bold')} {text}")

    def warn(self, text: str) -> None:
        self.say(f"{self.paint(self.g['warn'], 'yellow', 'bold')} {text}")

    def bad(self, text: str) -> None:
        self.say(f"{self.paint(self.g['bad'], 'red', 'bold')} {text}")

    def rule(self, char: Optional[str] = None) -> None:
        self.say(self.paint((char or self.g["h"]) * self.width, "grey"))

    def header(self, title: str, *styles: str) -> None:
        """A section title set into a rule: '── TITLE ─────'."""
        lead = self.g["h"] * 2 + " " + title + " "
        fill = self.g["h"] * max(self.width - len(lead), 0)
        self.say(self.paint(lead, *(styles or ("bold",))) + self.paint(fill, "grey"))

    def badge(self, text: str, colour: str) -> str:
        """A small filled label, e.g. a severity tag, using a 256-colour background."""
        if not self.color:
            return f"[{text}]"
        n = colour[1:] if colour.startswith("c") else colour
        return f"\x1b[1;30;48;5;{n}m {text} \x1b[0m"

    def sparkline(self, values: Sequence[int]) -> str:
        """One glyph per value, scaled 0..len(spark ramp)-1 against the highest value shown."""
        ramp = self.g["spark"]
        peak = max(values) if values and max(values) > 0 else 1
        return self.paint(
            "".join(ramp[min(len(ramp) - 1, round(v / peak * (len(ramp) - 1)))] for v in values),
            "yellow" if self.unicode else "",
        )

    def typed(self, text: str, delay: float = 0.012, *styles: str) -> None:
        """Print text one character at a time on a real terminal; instantly otherwise."""
        if not self.interactive:
            self.say(self.paint(text, *styles))
            return
        for ch in text:
            self.out.write(self.paint(ch, *styles))
            self.out.flush()
            time.sleep(delay)
        self.out.write("\n")
        self.out.flush()

    def banner(self) -> None:
        if not self.unicode:
            for line in BANNER:
                self.say(self.paint(line, "bold", "cyan"))
            return
        for line, shade in zip(BANNER_UNICODE, BANNER_GRADIENT):
            self.say(self.paint(line, shade, "bold"))

    def sigil(self) -> None:
        lines = EYE_SIGIL_UNICODE if self.unicode else EYE_SIGIL_ASCII
        for line in lines:
            self.say(self.paint(line.center(self.width), "red", "bold"))

    def clear(self) -> None:
        if self._can_clear:
            self.out.write("\x1b[2J\x1b[H")
            self.out.flush()

    def wrapped(self, text: str, first: str = "  ", rest: str = "  ", *styles: str, bar: str = "") -> None:
        """Word-wrap text under the given indents. With `bar` (a pre-painted single
        glyph), replace one indent column on every line with it, so a multi-line
        block carries a continuous coloured accent down its left edge."""
        width = max(20, self.width - 2)
        filled = textwrap.fill(text, width=width, initial_indent=first, subsequent_indent=rest)
        if bar:
            filled = "\n".join(
                line[:2] + bar + line[3:] if len(line) > 2 and line[2] == " " else line
                for line in filled.split("\n")
            )
        self.say(self.paint(filled, *styles))

    def box(self, lines: Sequence[str], *styles: str, double: bool = False) -> None:
        g = self.g
        tl, tr, bl, br, h, v = (
            (g["dtl"], g["dtr"], g["dbl"], g["dbr"], g["dh"], g["dv"]) if double
            else (g["tl"], g["tr"], g["bl"], g["br"], g["h"], g["v"])
        )
        inner = self.width - 4
        rows = []
        for line in lines:
            rows.extend(textwrap.wrap(line, inner) or [""])
        self.say(self.paint(tl + h * (self.width - 2) + tr, *styles))
        for row in rows:
            self.say(self.paint(v + " " + row.ljust(inner) + " " + v, *styles))
        self.say(self.paint(bl + h * (self.width - 2) + br, *styles))

    def panel(self, title: str, rows: Sequence[str], *styles: str) -> None:
        """A titled box whose rows may already contain colour codes.

        A row longer than the box is cut to fit (with an ellipsis) rather than left to overflow
        and break the border on the lines below it.
        """
        g = self.g
        inner = self.width - 4
        head = f"{g['h']} {title} "
        self.say(self.paint(g["tl"] + head + g["h"] * max(self.width - 2 - len(head), 0) + g["tr"], *styles))
        edge = self.paint(g["v"], *styles)
        for row in rows:
            over = visible_len(row) - inner
            if over > 0:
                plain = _ANSI.sub("", row)
                row = plain[: max(inner - 1, 0)] + "…"
            pad = " " * max(inner - visible_len(row), 0)
            self.say(f"{edge} {row}{pad} {edge}")
        self.say(self.paint(g["bl"] + g["h"] * (self.width - 2) + g["br"], *styles))

    @property
    def interactive(self) -> bool:
        isatty = getattr(self.out, "isatty", None)
        return bool(isatty and isatty())

    def bar(self, value: int, total: int, width: int = 20, *styles: str) -> str:
        """A text bar: filled part in the given styles, the rest grey."""
        total = max(total, 1)
        filled = int(round(width * min(max(value, 0), total) / total))
        return self.paint(self.g["full"] * filled, *styles) + self.paint(self.g["empty"] * (width - filled), "grey")

    def ask(self, prompt: str) -> str:
        if not prompt.endswith(" "):
            prompt += " "
        return self.read(self.paint(prompt, "bold", "green")).strip()


class Spinner:
    """A one-line live status for slow steps. Does nothing unless the console is interactive."""

    def __init__(self, console: Console):
        self.c = console
        self.text = ""
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def start(self, text: str) -> None:
        if not self.c.interactive:
            return
        self.text = text
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def update(self, text: str) -> None:
        self.text = text

    def _run(self) -> None:
        frames = self.c.g["spin"]
        n = 0
        while not self._stop.is_set():
            with self._lock:
                line = f"  {self.c.paint(frames[n % len(frames)], 'cyan', 'bold')} {self.text}"
                self.c.out.write("\r" + line + " " * max(self.c.width - visible_len(line) - 1, 0))
                self.c.out.flush()
            n += 1
            time.sleep(0.09)

    def stop(self) -> None:
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join()
        self._thread = None
        with self._lock:
            self.c.out.write("\r" + " " * (self.c.width - 1) + "\r")
            self.c.out.flush()
