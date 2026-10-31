# UniPCAP

Single-file telco core pcap analyzer. Open a capture in the browser and get:

- **Overview** — DNS rates, GTP-U volume/quality, Gx/Gy quota reporting, negative
  signaling responses, and subscriber identities (IMSI/MSISDN with per-protocol fallback).
- **Signaling ladder** — one row per message for S1AP, NGAP, GTPv2, PFCP, Diameter, SIP,
  CAMEL and SGsAP, with request→response pairing, per-message decode on click, and
  user-plane burst arrows.
- **Auto-labelled nodes** — MME, PGW, SGW, PCRF, HSS, STP, UPF, etc., inferred from
  the traffic itself.

Windows-first (the UI is a local web server + WebView2 desktop shell), decode by Wireshark.

## Requirements

- Windows 10/11
- [Wireshark](https://www.wireshark.org/download.html) (tshark is the decode engine)
- Python 3.12 (dev only; the release build is a standalone exe)

If tshark is not on `PATH`, point `UNIPCAP_TSHARK` at `tshark.exe`.

## Run from source

```powershell
uv sync --extra dev
uv run python -m unipcap                 # opens the UI in your browser
uv run python -m unipcap --analyze x.pcap --out x.json   # headless: JSON, no UI
```

`--port N` picks the UI port (`0` = any free one), `--no-browser` serves without opening.

## Build a portable release

```powershell
pwsh scripts/build.ps1 -Version 0.1.0    # dist\unipcap-0.1.0-win64.zip
pwsh scripts/smoke.ps1                   # headless + UI checks on the built exe
```

`.github/workflows/release.yml` does the same on a `v*` tag and attaches the zip.

## Tests

```powershell
uv run python -m pytest -q              # needs a real tshark; ~3 min
```

## Notes

- `samples/` is local-only (gitignored): real captures and their expected-output fixtures
  live there but never ship.
- `THIRD_PARTY.md` lists bundled components (WebView2 runtime).
