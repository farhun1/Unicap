import struct
from pathlib import Path

ETH = b"\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x01\x08\x00"


def ip(src: str, dst: str, proto: int, body: bytes) -> bytes:
    # existing _ip without the ETH prefix
    ipa = lambda a: bytes(int(x) for x in a.split("."))
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, proto, 0, ipa(src), ipa(dst)) + body


def _ip(src: str, dst: str, proto: int, body: bytes) -> bytes:
    return ETH + ip(src, dst, proto, body)


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    # checksums left 0: tshark still dissects, just flags them
    return _ip(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload)


def dns(src: str, dst: str, qid: int, resp: bool = False, rcode: int = 0, answers: int = 0) -> bytes:
    flags = (0x8180 | rcode) if resp else 0x0100
    body = struct.pack("!HHHHHH", qid, flags, 1, answers, 0, 0)
    body += b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    for _ in range(answers):
        body += struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + b"\x01\x02\x03\x04"
    return udp(src, dst, 40000, 53, body)


def gtpu_gpdu(src: str, dst: str, teid: int, seq: int, payload: bytes = b"", sn: bool = True) -> bytes:
    flags = 0x32 if sn else 0x30
    hdr = struct.pack("!BBHI", flags, 0xFF, 8 + (4 if sn else 0) + len(payload), teid)
    if sn:
        hdr += struct.pack("!HBB", seq, 0, 0)
    return udp(src, dst, 2152, 2152, hdr + payload)


def gtpu_echo(src: str, dst: str, teid: int, seq: int, resp: bool = False) -> bytes:
    hdr = struct.pack("!BBHIHBB", 0x32, 0x02 if resp else 0x01, 12, teid, seq, 0, 0)
    return udp(src, dst, 2152, 2152, hdr)


def tcp(src: str, dst: str, sport: int, dport: int, seq: int, payload: bytes = b"", ack: int = 0) -> bytes:
    # segment only: src/dst ride in the ip() wrapper, which carries proto 6
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, 0x5018, 65535, 0, 0) + payload


def sctp_data(src: str, dst: str, sport: int, dport: int, ppid: int, payload: bytes, tsn: int = 1) -> bytes:
    n = 16 + len(payload)
    chunk = struct.pack("!BBHIHHI", 0, 3, n, tsn, 0, 0, ppid) + payload + b"\x00" * (-n % 4)
    return _ip(src, dst, 132, struct.pack("!HHII", sport, dport, 1, 0) + chunk)


def diameter_ccr() -> bytes:
    """Minimal Gy CCR (cmd 272, app 4) with CC-Total-Octets 1024; Session-Id must parse."""

    def avp(code: int, value: bytes) -> bytes:
        pad = (-len(value)) % 4
        return (struct.pack("!IB", code, 0x40) + struct.pack("!I", 8 + len(value) + pad)[1:]
                + value + b"\x00" * pad)

    body = (avp(263, b"host.example.com;1234;5678;0")   # Session-Id
            + avp(258, struct.pack("!I", 4))            # Auth-Application-Id: Gy
            + avp(421, struct.pack("!Q", 1024)))        # CC-Total-Octets: AVP 421, Unsigned64
    return (struct.pack("!B", 1) + struct.pack("!I", 20 + len(body))[1:]
            + struct.pack("!B", 0xC0) + struct.pack("!I", 272)[1:]
            + struct.pack("!III", 4, 0x11111111, 0x22222222)) + body


def identity_ie(typ: int, digits: str) -> bytes:
    # TS 29.002 BCD, low nibble first, 0xF pad; 0x00 instance, IE len header
    ds = [int(c) for c in digits] + [0xF]
    val = bytes(ds[i] | (ds[i + 1] << 4) for i in range(0, len(ds), 2))
    return struct.pack("!BHB", typ, len(val), 0) + val


def gtpv2_csr(src: str, dst: str, fteids: list[tuple[int, str]],
              imsi: str | None = None, msisdn: str | None = None) -> bytes:
    ies = (identity_ie(1, imsi) if imsi else b"") + (identity_ie(76, msisdn) if msisdn else b"")
    for inst, (iface, ip) in enumerate(fteids):
        val = struct.pack("!BI4s", 0x80 | iface, 1000 + inst, bytes(int(x) for x in ip.split(".")))
        ies += struct.pack("!BHB", 87, len(val), inst) + val
    msg = struct.pack("!BBHI", 0x48, 32, 8 + len(ies), 0) + b"\x00\x00\x01\x00" + ies
    return udp(src, dst, 2123, 2123, msg)


def write(path: Path, frames: list[bytes], times: list[float] | None = None) -> Path:
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    for i, f in enumerate(frames):
        sec, usec = divmod(round((times[i] if times else i) * 1_000_000), 1_000_000)
        out += [struct.pack("<IIII", 1_700_000_000 + sec, usec, len(f), len(f)), f]
    path.write_bytes(b"".join(out))
    return path


# One-frame GTPv2 Create Session Request used by several tests. It is generated
# at test time, never committed: no capture file may enter git (see
# tests/test_user_data_guard.py). Its name stays stable because tests assert it.
FIXTURE_NAME = "gtpv2_csr.pcap"


def ensure_gtpv2_csr_fixture(path: Path) -> Path:
    """Create the canonical test capture if it is missing, and return it."""
    if not path.is_file():
        path.parent.mkdir(parents=True, exist_ok=True)
        write(path, [gtpv2_csr("10.3.0.1", "10.4.0.1",
                               [(10, "10.3.0.1"), (7, "10.5.0.1")])])
    return path


if __name__ == "__main__":  # python tests/pcapgen.py
    print(ensure_gtpv2_csr_fixture(Path(__file__).parent / "fixtures" / FIXTURE_NAME))
