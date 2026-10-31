import argparse
import json
import sys
import webbrowser
from pathlib import Path

from .capture import summarise
from .serve import Server
from .tshark import TsharkNotFound, find_tshark


def _notify(msg: str) -> None:
    """Windowed exe has no console; a message box is the only way to show a fatal error."""
    if sys.platform == "win32":
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, msg, "UniPCAP", 0x10)
    elif sys.stderr:
        print(msg, file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="unipcap")
    ap.add_argument("--analyze", metavar="PCAP")
    ap.add_argument("--out", metavar="JSON")
    ap.add_argument("--port", type=int, default=0, help="local UI port (0 = pick a free one)")
    ap.add_argument("--no-browser", action="store_true", help="serve the UI without opening a browser")
    a = ap.parse_args(argv)
    if a.analyze:
        # windowed exe has no stdout, so results (and errors) go to a file
        if not a.out:
            ap.error("--analyze requires --out")
        try:
            data, rc = summarise(Path(a.analyze)), 0
        except Exception as e:
            data, rc = {"error": str(e) or type(e).__name__}, 1
        Path(a.out).write_text(json.dumps(data), encoding="utf-8")
        return rc
    try:
        find_tshark()
    except TsharkNotFound as e:
        _notify(str(e))
        return 1
    try:
        server = Server(port=a.port)
    except (OSError, OverflowError) as e:
        _notify(f"Cannot start UniPCAP on port {a.port}: {e}")
        return 1
    server.start()
    if not a.no_browser and not webbrowser.open(server.url):
        _notify(f"Open this URL in your browser:\n{server.url}")
    try:
        server.wait()
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
