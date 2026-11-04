# UniPCAP

Single-file telco core pcap analyzer. Open a capture in the browser and get:

- **Overview** — DNS rates, GTP-U volume/quality, Gx/Gy quota reporting, negative
  signaling responses, and subscriber identities (IMSI/MSISDN with per-protocol fallback).
- **Signaling ladder** — one row per message for S1AP, NGAP, GTPv2, PFCP, Diameter, SIP,
  CAMEL and SGsAP, with request→response pairing, per-message decode on click, and
  user-plane burst rows.
- **Auto-labelled nodes** — MME, PGW, SGW, PCRF, HSS, STP, UPF, etc., inferred from
  the traffic itself, each with the evidence that produced the label.

Windows-first. The UI is a local web server bound to `127.0.0.1` (random token in the
URL) that opens in your default browser; nothing is installed and nothing leaves the
machine. All protocol decoding is done by Wireshark's `tshark`.

## Requirements

- Windows 10/11
- [Wireshark](https://www.wireshark.org/download.html) — `tshark` is the decode engine
- Python 3.12 (dev only; the release build is a standalone exe)

`tshark` is found via `UNIPCAP_TSHARK` (full path to `tshark.exe`), then `PATH`, then
`%ProgramFiles%\Wireshark`.

## Run from source

```powershell
uv sync --extra dev
uv run python -m unipcap                 # opens the UI in your browser
uv run python -m unipcap --analyze x.pcap --out x.json   # headless: JSON, no UI
```

`--port N` picks the UI port (`0` = any free one), `--no-browser` serves without opening.
The server shuts down a few seconds after the last browser tab closes.

## Using the UI

- **Open a capture** with the button, by dropping a file anywhere on the page, or
  `Ctrl`/`Cmd` + `O`. Supported: `.pcap`, `.pcapng`, `.cap`, `.gz`.
- **Ladder tabs**: *Overview* (metrics), *GTPC* (signalling messages), *GTPU*
  (user-plane flows). Click a message or flow to read its decode/detail beside the ladder.
- **Filters**: one box searches messages (name, protocol, node, frame) and one searches
  nodes (IP, hostname, role, protocol, evidence). Both filter the whole capture, not just
  the rows on screen, and show live counts.
- **Node focus**: click a node header to see only that node's flows; click again to clear.
- **Keyboard**: `/` focuses the ladder filter, `↑`/`↓`/`PageUp`/`PageDown`/`Home`/`End`
  move through messages, `Enter`/`Space` selects, `←`/`→` switch tabs, `Esc` backs out of
  the overlay filter → detail → node focus → filters in that order.
- Large captures are fine: the ladder keeps its full scroll height but only renders the
  visible rows, so a 30k-message trace stays responsive.

## Headless JSON

`--analyze capture.pcap --out out.json` writes one object with these keys:

| Key | Contents |
|---|---|
| `file` | name, frame count, start/end (ISO-8601 UTC), duration |
| `warnings` | analysis caveats (undecoded SCTP, cut-short files, size budgets) |
| `protocols` | `[name, frame_count]`, most common first |
| `nodes` | per IP: roles, interfaces, hostnames, evidence, protocols, frames |
| `ladder` | nodes, messages (with decodes), user-plane bursts, request→response pairs |
| `overview` | DNS / GTP-U / Gx / Gy / subscriber / negative-response metrics |

The web UI consumes exactly this payload. Errors are reported as `{"error": "..."}` with
exit code 1, so a failed analysis never looks like an empty capture.

## Build a portable release

```powershell
pwsh scripts/build.ps1 -Version 0.1.0    # dist\unipcap-0.1.0-win64.zip
pwsh scripts/smoke.ps1                   # headless + UI checks on the built exe
```

The exe is a one-folder PyInstaller build: unzip and run `unipcap.exe`. Wireshark is not
bundled, so the machine still needs it installed (`smoke.ps1` proves the installed copy is
found without a bundled one). `.github/workflows/release.yml` runs the tests, builds the
zip and publishes it on every push to `main`, tagging `v<version>-r<run-number>`.

## Tests

```powershell
uv run python -m pytest -q              # needs a real tshark; ~2-3 min
```

The suite covers the analyzer, role inference, ladder pairing/decoding, the overview
metrics, the HTTP server surface, the CLI, the release workflow PowerShell, the shipped
web assets, and the subscriber-data guard that keeps captures out of git. If `tshark` is
not on `PATH`, set `UNIPCAP_TSHARK` first.

## Notes

- **No capture ever ships.** Every capture format — `.pcap`, `.pcapng`, `.cap`,
  `.dmp`, `.snoop`, `.erf`, and gzipped captures (`.gz`) — is gitignored in every
  directory, because captures carry subscriber data (IMSI/MSISDN, operator addressing,
  private IPs). `samples/` is local-only and only its `README.md` ships. The tests' own
  capture fixture is generated at run time by `tests/conftest.py`/`tests/pcapgen.py`,
  never committed, so a fresh checkout still runs the suite.
- A pre-commit hook refuses any capture even after `git add -f`. Enable it once per
  clone:

  ```powershell
  git config core.hooksPath .githooks
  ```

  `tests/test_user_data_guard.py` asserts the ignore rules for every format and
  directory, scans the tracked files and the full history, checks that the fixture is
  untracked and can be regenerated, and runs the hook in a throwaway repository — so a
  future edit cannot quietly make captures publishable.
- `THIRD_PARTY.md` lists bundled components (none: Wireshark is an external dependency).
