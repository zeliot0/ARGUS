# ARGUS

**A read-only, offline indicator-of-compromise scanner for Windows, macOS and Linux.**

Point it at a machine. It checks that machine against published IOC feeds — domains, IPs,
file hashes, filenames — across browsers, autostart entries, running processes, open ports,
WMI/COM persistence, DNS cache, shell history and more. It never touches the network, never
writes to the system it scans, and it never tells you a machine is "clean." It tells you what
it checked, what it found, and — just as loudly — what it *couldn't* check.

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-informational)](#)
[![Dependencies: none](https://img.shields.io/badge/dependencies-standard%20library%20only-success)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

```
 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
 v0.8.2  read-only, offline indicator scanner  ·  Windows, macOS, Linux

╭─ STATUS ─────────────────────────────────────────────────────────────────────╮
│ ● ARGUS ONLINE   ● NETWORK LOCKED   ● READ-ONLY                              │
│                                                                              │
│ Feed       3 of 12 switched on  (1,842 indicators)                           │
│ Last scan  none yet                                                          │
╰──────────────────────────────────────────────────────────────────────────────╯

╭─ MAIN MENU ──────────────────────────────────────────────────────────────────╮
│ [1] Full scan        all checks, hashes file contents                        │
│ [2] Quick scan       all checks, skips file hashing                          │
│ [3] Custom scan      pick which checks to run                                │
│ [4] Indicator feeds  switch campaigns on or off, load a CSV                  │
│ [5] Reports          view, save, open in browser                             │
│ [6] Settings         limits and colour                                       │
│ [7] About            what ARGUS does and does not do                         │
│ [8] Checks           what each check looks at, and last scan's numbers       │
│ [0] Exit                                                                     │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## The problem

Researchers publish solid evidence of real spyware and malware campaigns: domains, IPs, file
hashes used by tools like Pegasus, Predator, FinFisher, DoNot, and plenty of less famous
malware. That data is public. What's missing is the boring part — actually checking whether
any of it shows up on a real machine.

Right now that usually means one of:

- **Trusting a closed-source antivirus** to already know about it, with no way to check, while
  it sends its own telemetry off the machine.
- **Uploading logs to a third-party cloud service** — a bad idea if you suspect you're the one
  being watched.
- **Grepping by hand** across a different registry layout, browser database, and log format on
  every OS, redone from scratch every time a new campaign gets published.
- **Paying for incident-response tooling** built for professional responders, when you just
  want to know if your own laptop shows up in a published IOC list.

ARGUS closes that specific gap: feed it a CSV of known indicators and it tells you, offline and
in plain language, whether any of it is on this machine — the same way, whether that machine is
running Windows, macOS, or Linux.

## Why ARGUS

Most "is my computer infected" tools either phone home, demand an install, or hand you a green
checkmark that means nothing. ARGUS does the opposite on purpose:

- **Offline by design.** The socket layer is patched to raise the moment anything in the
  process tries to connect, send, or resolve a hostname — not a config flag, a guarantee
  enforced while the scan runs.
- **Read-only.** Nothing is modified, deleted, or quarantined. Locked browser databases are
  copied out, read, and the copy is discarded.
- **No fake confidence.** A result is never reported as clean unless every check actually ran.
  Every scan ends with a **COULD NOT CHECK** section naming exactly what was skipped and why.
- **No cloud, no account, no telemetry.** Standard-library-only Python. Nothing leaves the
  machine, because nothing can.
- **Built on named, sourced evidence.** Every indicator traces back to a published feed
  (Citizen Lab's AdFection report, Amnesty International's Security Lab investigations into
  Pegasus, Predator, FinFisher and others) — not a secret heuristic model guessing at you.

## Quick start

```bash
git clone https://github.com/zeliot0/ARGUS.git
cd ARGUS/recon-scanner
python3 argus.py          # Windows: py -3 argus.py
```

That opens the numbered menu above. Prefer scripting it?

```bash
python3 -m scanner --feeds                          # every feed switched on in iocs/
python3 -m scanner --ioc a.csv --ioc b.csv --quick  # specific files, merged
python3 -m scanner --feeds --json report.json       # machine-readable output
```

Exit codes: `0` nothing matched, `2` at least one actionable match, `1` setup error.

Want it on your `PATH`?

```bash
pip install -e .      # then: argus   or   argus --feeds --quick
```

## What it checks

| Check | Windows | macOS | Linux |
|---|---|---|---|
| Browser history and cookie host names (Chrome, Edge, Brave, Firefox) | ✔ | ✔ | ✔ |
| File names and SHA-256 in Downloads, Desktop, Documents, Temp, AppData | ✔ | ✔ | ✔ |
| Auto-start entries | Run/RunOnce keys, services, scheduled tasks, Startup folder | LaunchAgents/Daemons, cron, login items | autostart, systemd units, cron |
| Hosts file entries | ✔ | ✔ | ✔ |
| DNS resolver cache | ✔ | — | — |
| Live network connections against IP indicators | ✔ | ✔ | ✔ |
| WMI event subscriptions and per-user COM class overrides | ✔ | — | — |
| Installed browser extensions (ID and name) | ✔ | ✔ | ✔ |
| Shell / PowerShell command history | ✔ | ✔ | ✔ |
| Running processes, by on-disk SHA-256 and by name | ✔ | ✔ | ✔ |
| Listening TCP ports, by owning process name | ✔ | ✔ | ✔ |

11 checks, cross-platform, all against the same indicator set.

## Beyond a single scan

- **History** — every scan is logged under `reports/history/`. The next scan shows you what's
  **new** and what's **resolved**, and a check that didn't run is never reported as "resolved."
- **Baseline** — snapshot every autostart entry, WMI/COM item and listening port on a known-good
  day, and later scans flag what's **new since then** — a signal independent of any feed, for the
  thing no published indicator knows about yet.
- **Reviewed findings** — mark a finding reviewed once you've looked into it; it's filtered from
  the threat level and findings list from then on, without ever being deleted from the saved
  report.
- **Reports** — every scan is saved as `.txt`, `.json`, and a self-contained `.html` (no scripts,
  no external resources, every value escaped) that opens straight in a browser.

## Indicator feeds

One CSV per campaign under `iocs/`. Shipped feeds include Citizen Lab's AdFection report and
Amnesty International Security Lab spyware investigations (Pegasus, Predator, FinFisher, DoNot,
Wintego Helios, NoviSpy, and more) — all CC-BY, credited per row. Phishing-infrastructure feeds
ship **off by default** since they're broad and more likely to produce weak leads. Switch feeds
on or off from the menu, or drop in your own:

```
kind,value,tier,confidence,source
domain,evil.example,lead,medium,your-source-here
```

`kind` is `domain`, `ip`, `sha256`, `filename`, or `extension`. `tier` is `confirmed` or `lead`
(a lead drops the severity one level). Every row needs a `source`.

## Guarantees and limits

- **No network.** Enforced at the socket layer for the duration of the scan.
- **No writes** to the scanned system.
- **Cookies:** only host names and timestamps are read — never values.
- Matches are leads, not proof of infection. A match means "investigate," not "infected."
  Output is defanged (`evil[.]example`) so a report is safe to paste elsewhere.

## Tests

214 tests, no network, no admin rights required.

```bash
python3 -m unittest discover -s tests -t .
```

## Not yet covered

Browser caches / local storage, the Windows DNS-Client event log, signed feed updates, and
macOS's newer binary-plist background-task store (only the older login-items plist is read).
The listening-port check never flags a port just for being open — there's no verified "bad
ports" list to back that claim — only a listener whose process name matches a filename
indicator.

Contributions closing any of these are welcome.

## Contributing

Issues and pull requests are welcome — new checks, more feeds, platform coverage, or just
pointing out where a claim in a report overstates what was actually verified. If you add a
check, it should follow the same rule everything else here does: name what it looked at, and
say plainly when it couldn't look.

## License

MIT — see [LICENSE](LICENSE).

## Author

Developed by Salim, from Tunisia.
