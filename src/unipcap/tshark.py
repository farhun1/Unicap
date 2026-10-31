import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path


class TsharkNotFound(RuntimeError):
    pass


class TsharkError(RuntimeError):
    pass


INSTALL_HINT = ("tshark not found. Install Wireshark from "
                "https://www.wireshark.org/download.html, or set UNIPCAP_TSHARK "
                "to the full path of tshark.exe")


def find_tshark() -> Path:
    env = os.environ.get("UNIPCAP_TSHARK")
    if env and Path(env).is_file():
        return Path(env)
    if found := shutil.which("tshark"):
        return Path(found)
    for var in ("ProgramFiles", "ProgramFiles(x86)"):
        if d := os.environ.get(var):
            p = Path(d) / "Wireshark" / "tshark.exe"
            if p.is_file():
                return p
    raise TsharkNotFound(INSTALL_HINT)


_EMPTY_PROFILE = tempfile.mkdtemp(prefix="unipcap-ws-")  # keeps a personal Wireshark profile out of results


def iter_fields(pcap: Path, fields: list[str], display_filter: str = "",
                warnings: list[str] | None = None,
                decode_as: list[str] = ()) -> Iterator[dict[str, str]]:
    cmd = [str(find_tshark()), "-n", "-r", str(pcap)]
    for rule in decode_as:
        cmd += ["-d", rule]
    cmd += ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=|"]
    if display_filter:
        cmd += ["-Y", display_filter]
    for f in fields:
        cmd += ["-e", f]
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    with tempfile.TemporaryFile() as err:  # file, not PIPE: avoids deadlock when stdout is consumed lazily
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err, creationflags=flags,
                                env={**os.environ, "WIRESHARK_CONFIG_DIR": _EMPTY_PROFILE},
                                encoding="utf-8", errors="replace")
        n = 0
        try:
            for line in proc.stdout:
                n += 1
                yield dict(zip(fields, line.rstrip("\n").split("\t")))
            proc.wait()
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait()
            proc.stdout.close()
        if proc.returncode:
            err.seek(0)
            msg = err.read().decode("utf-8", "replace").strip()
            if not n:
                raise TsharkError(msg)
            if warnings is not None:
                warnings.append(msg)


def iter_verbose(pcap: Path, display_filter: str,
                 warnings: list[str] | None = None,
                 decode_as: list[str] = (),
                 options: list[str] = ()) -> Iterator[tuple[int, str]]:
    cmd = [str(find_tshark()), "-n", "-r", str(pcap)]
    for rule in decode_as:
        cmd += ["-d", rule]
    for o in options:
        cmd += ["-o", o]
    cmd += ["-Y", display_filter, "-V"]
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    with tempfile.TemporaryFile() as err:  # file, not PIPE: avoids deadlock when stdout is consumed lazily
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err, creationflags=flags,
                                env={**os.environ, "WIRESHARK_CONFIG_DIR": _EMPTY_PROFILE},
                                encoding="utf-8", errors="replace")
        n = 0
        try:
            frame, block = 0, []
            for line in proc.stdout:
                if m := re.match(r"^Frame (\d+): ", line):
                    if block:
                        n += 1
                        yield frame, "".join(block).rstrip("\n")
                    frame, block = int(m.group(1)), []
                block.append(line)
            if block:
                n += 1
                yield frame, "".join(block).rstrip("\n")
            proc.wait()
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait()
            proc.stdout.close()
        if proc.returncode:
            err.seek(0)
            msg = err.read().decode("utf-8", "replace").strip()
            if not n:
                raise TsharkError(msg)
            if warnings is not None:
                warnings.append(msg)


def vals(row: dict[str, str], field: str) -> list[str]:
    v = row.get(field, "")
    return v.split("|") if v else []
