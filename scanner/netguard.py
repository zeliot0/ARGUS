"""Block network access for the lifetime of a scan.

This is defence in depth inside the Python process. It is not an operating-system
sandbox: a subprocess started by a check would not be covered. The scanner's own
checks never start network-capable subprocesses.
"""
from __future__ import annotations

import socket


class NetworkAttempt(RuntimeError):
    """Raised when any code path tries to open or resolve a network address."""


_installed = False


def _blocked(*_args, **_kwargs):
    raise NetworkAttempt("network access is disabled during a scan")


def install() -> None:
    """Patch the socket layer so every connect, send or DNS lookup raises."""
    global _installed
    if _installed:
        return
    socket.socket.connect = _blocked
    socket.socket.connect_ex = _blocked
    socket.socket.sendto = _blocked
    socket.getaddrinfo = _blocked
    socket.gethostbyname = _blocked
    socket.gethostbyname_ex = _blocked
    _installed = True
