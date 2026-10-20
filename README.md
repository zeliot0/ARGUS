# ARGUS

A read-only, offline scanner that checks a Windows, macOS or Linux computer for traces of
published indicators of compromise (IOCs). Python 3.8+, standard library only.

## Run

    py -3 argus.py                      (Windows)   python3 argus.py   (macOS / Linux)

This opens the numbered menu: run a scan, manage indicator feeds, view / save / open reports,
settings. Scripted use:

    python3 -m scanner --feeds                          # every feed switched on in iocs/
    python3 -m scanner --ioc a.csv --ioc b.csv --quick  # specific files, merged
    python3 -m scanner --feeds --json report.json

Exit codes: `0` no actionable match, `2` at least one match (not `info`), `1` setup error.

## Indicator feeds

One CSV per campaign in `iocs/`; the file name is the campaign name. Use menu 4 (Indicator
feeds) to switch feeds on or off; the choice is saved in `iocs/feeds.json`.

- Shipped: AdFection (Citizen Lab), plus Amnesty Security Lab spyware investigations
  (Pegasus, Predator, FinFisher, DoNot, Wintego Helios, NoviSpy and others).
- Phishing-infrastructure lists (`phishing-*.csv`) are **off by default**; they are broad
  and more likely to produce weak leads.
- `sample.csv` (fake test values) and `unverified-candidates.csv` are never loaded.
- Amnesty feeds are CC-BY (https://github.com/AmnestyTech/investigations); each row says so
  in its `source` column.

Format (UTF-8, `#` starts a comment):

    kind,value,tier,confidence,source

`kind` is `domain`, `ip`, `sha256` or `filename`. `tier` is `confirmed` or `lead` (lead drops
one severity level). Every row needs a `source`.

## What it checks

| Check | Windows | macOS | Linux |
|---|---|---|---|
| Browser history and cookie host names | yes | yes | yes |
| File names and SHA-256 in user folders | yes | yes | yes |
| Auto-start entries | HKCU + HKLM Run/RunOnce, services, scheduled tasks, Startup folders | LaunchAgents/Daemons, cron, login items | autostart, systemd units, cron |
| Hosts file | yes | yes | yes |
| DNS resolver cache | yes | not yet | not yet |
| Live connections to indicator IPs | yes | yes | yes |
| WMI event subscriptions, per-user COM overrides | yes | not yet | not yet |
| Installed browser extensions (ID and name) | yes | yes | yes |
| Shell / PowerShell command history | yes | yes | yes |
| Running processes (on-disk SHA-256 and name) | yes | yes | yes |
| Listening TCP ports (by owning process name) | yes | yes | yes |

Every run prints a **COULD NOT CHECK** section. A result is never described as clean unless
every check ran and nothing was skipped.

## Smarter file scanning

Cache and dependency folders (Chrome caches, `node_modules`, ...) are skipped by default so the
per-folder budget goes to places a dropped file is plausible; every skip is listed under
COULD NOT CHECK. Use `--deep` (or Settings → Deep file scan) to include them. Locked browser
databases are read with shared access on Windows, so Chrome can stay open (if it still refuses,
close the browser and rescan).

## History

Each scan is recorded in `reports/history/`. After a scan ARGUS shows what is **new** and what
is **resolved** since the previous one (Reports → 5 repeats it). Checks that did not run are
never reported as resolved.

## Baseline (new-since-snapshot)

The checks above only flag what matches a published feed. `Reports -> Baseline` records every
autostart entry, WMI/COM item and listening port on a clean day; a later scan then shows what is
**new since that snapshot**, even if it matches nothing in any feed. This is a heuristic signal,
not an indicator match -- a software update or a new install shows up here too -- but it is the
one place ARGUS can catch something no feed knows about yet.

## Reviewed findings

After you have looked into a finding and decided it is not a concern, mark it reviewed
(Reports → 6). It is then hidden from the threat level and the findings list in every later
report of that exact finding (same check, grade, indicator and location), and un-marking it is
one menu away. Reviewing a finding never deletes it from the saved JSON report — only the
display is filtered.

## Install as a command

    pip install -e .      # then run:  argus   or   argus --feeds --quick

Use an editable install (`-e`) so the command keeps finding the `iocs/` feeds in this folder.

## Reports

Saved to the reports folder as `.txt`, `.json` and a self-contained `.html` (no scripts, no
external resources, every value escaped). Menu 5 → 4 opens the latest HTML in your browser.

## Guarantees and limits

- **No network.** Socket connect, send and DNS lookup are patched to raise (a guard inside the
  Python process, not an OS sandbox).
- **No writes** to the scanned system. Browser databases are copied to a temp folder, read,
  and removed.
- **Cookies:** only host names and timestamps are read, never values.
- Matches are leads, not proof of infection. Output is defanged.

## Tests

    py -3 -m unittest discover -s tests -t .

## Not yet covered

Browser caches / local storage, Windows DNS-Client log, signed feed updates, macOS background
task items stored as binary plists (only the older login-items plist is read). The listening-port
check does not flag a port for being open -- it has no verified list of "bad" ports -- only a
listener whose process name matches a filename indicator.

## Author

Developed by Salim, from Tunisia.
