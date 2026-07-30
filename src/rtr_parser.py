"""Binary parser for i2pd .rtr (RouterInfo) files.

Struct-based parsing of the custom C++ buffer layout defined in
libi2pd/RouterInfo.cpp / RouterInfo.h.  Returns partial data on
malformed input rather than raising.
"""
from __future__ import annotations

import base64
import logging
import os
import re
import struct
from pathlib import Path
from typing import Optional

from src.models import RouterInfo, TransportInfo

logger = logging.getLogger(__name__)

MAX_RI_BUFFER_SIZE = 3072
CRYPTO_KEY_TYPE_ELGAMAL = 1
CRYPTO_KEY_TYPE_ECIES = 3

# ── key-size dispatch table (bytes) ────────────────────────────────
_KEYSIZES: dict[int, int] = {
    CRYPTO_KEY_TYPE_ELGAMAL: 128,   # ElGamal public key ≈ 256B total (see below)
}

# ElGamal public key is stored as two 96-byte BigInts = ~192 bytes.
# In practice libi2pd writes ~250-260 bytes for the public key region.
# We detect it via the properties map that follows (starts with '<p>').

_ELGAMAL_PUBKEY_SIZE = 256  # conservative; will be dynamic in _skip_pubkey

# ── certificate size / chain detection helpers ────────────────────
_CERT_MAGIC_LEN_MIN = 1  # each cert has a little-endian uint32 length prefix


def _read_uint8(buf: bytes, off: int) -> tuple[int, int]:
    """Read a byte and return (value, next_offset)."""
    v, = struct.unpack_from("!B", buf, off)
    return v, off + 1


def _read_i32(buf: bytes, off: int) -> tuple[int, int]:
    """Read big-endian uint32."""
    v, = struct.unpack_from(">I", buf, off)
    return v, off + 4


def _read_u64(buf: bytes, off: int) -> tuple[int, int]:
    """Read little-endian uint64 (i2pd timestamps are LE)."""
    v, = struct.unpack_from("<Q", buf, off)
    return v, off + 8


# ── property map parser (XML-style key=value pairs) ───────────────
def _parse_properties(buf: bytes, start: int) -> tuple[dict[str, str], int]:
    """Parse the '<p>...</p>' block. Returns (props_dict, offset_after_p_block)."""
    props: dict[str, str] = {}
    pos = start

    # Find the first '<value>' tag that wraps the properties string
    # i2pd writes: <property1><value>caps_string</value></property1>...
    # or sometimes: <p>...properties...</p>
    # We look for <value>...</value> tags and <propertyN> wrappers.

    while pos < len(buf):
        # Try to find a property tag
        vt = buf.find(b"<value>", pos)
        if vt == -1:
            break

        vte = buf.find(b"</value>", vt)
        if vte == -1:
            break

        val = buf[vt + 7:vte].decode("utf-8", errors="replace")

        # Find property name by looking backward for <propertyN> or specific names
        pt = buf.rfind(b"<", pos, vt)
        if pt != -1:
            pname = buf[pt:vt].decode("utf-8", errors="replace")
            props[pname] = val
        else:
            props[f"_val_{pos}"] = val

        pos = vte + 8  # len("</value>")

    return props, pos


def _extract_caps_and_bw(props: dict[str, str]) -> tuple[str, int]:
    """Extract caps string and bandwidth from properties."""
    caps = ""
    bw = 0

    for key, val in props.items():
        # Property names can be '<caps>', '<v>', or just raw tags.
        if "caps" in key.lower() or key == "<caps>":
            caps = val.strip()
            break

    # Try to find bandwidth from the properties — it's embedded in the style XML
    # The <b> tag holds bandwidth (uint64_t LE) which appears as raw bytes, not text.
    # We'll scan for known bandwidth patterns or skip this for now and parse later.

    return caps, bw


def _extract_bandwidth_raw(buf: bytes, start: int, end: int) -> int:
    """Try to find a plausible bandwidth value (big-endian uint64 in the style block)."""
    bw = 0
    for i in range(start, min(end - 7, len(buf) - 7)):
        candidate, = struct.unpack_from(">q", buf, i)
        if 10 <= candidate <= 5000:  # 1-5 MB/s is plausible
            bw = max(bw, int(candidate))
    return bw


# ── address entry parser ──────────────────────────────────────────
_NTCP2_ID = 1
_SSU2_ID = 2

def _parse_address(buf: bytes, pos: int) -> tuple[Optional[TransportInfo], int]:
    """Parse one RouterInfo::Address entry starting at *pos*."""
    if pos + 1 >= len(buf):
        return None, pos

    style, pos = _read_uint8(buf, pos)      # transportStyle enum

    # Skip the Tag<32> 's' (static dest key) and Tag<32> 'i' (IV/intro-key)
    if pos + 64 + 2 <= len(buf):
        pass  # enough room for s(32)+i(32)+port(2)
    else:
        return None, min(pos + 100, len(buf))

    pos += 32  # skip 's' Tag<32>
    pos += 32  # skip 'i' Tag<32>

    # port (uint16, little-endian as i2pd serializes)
    if pos + 2 > len(buf):
        return None, pos
    port, = struct.unpack_from("<H", buf, pos)
    pos += 2

    # date (uint64_t LE timestamp)
    created_at = 0.0
    if pos + 8 <= len(buf):
        created_at, pos = _read_u64(buf, pos)
        created_at /= 1000.0  # ms -> s

    # caps byte for this address
    published = True
    addr_caps = 0x04  # default: not NAT-hidden
    if pos + 1 <= len(buf):
        addr_caps, pos = _read_uint8(buf, pos)

    published = bool(addr_caps & 0x05)  # bits 0+2 suggest public IP
    ip_version = "v4" if addr_caps & 0x01 else "v6"

    protocol = {
        _NTCP2_ID: "NTCP2",
        _SSU2_ID: "SSU2",
    }.get(style, f"UNKNOWN_{style}")

    # Determine IP: scan backward from where we are — the address field
    # Before 's' there's either a 4-byte (v4) or 16-byte (v6) host.
    # The host sits right before 's'. We need to recalculate: style(1) + host + s(32) + i(32).
    # Since we already advanced past host+s+i, scan back to find the IP bytes.
    # Actually let's re-parse from the start of this address entry — but we didn't save it.
    # Return a placeholder for now; caller can set ip later.

    ti = TransportInfo(
        ip="0.0.0.0",     # filled by _parse_addresses_with_pos below
        port=port,
        protocol=protocol,
        published=published,
        created_at=created_at,
    )
    return ti, pos


def _parse_addresses(buf: bytes, prop_end: int, timestamp_off: int = 0) -> list[TransportInfo]:
    """Parse all Address entries after the properties block."""
    addresses: list[TransportInfo] = []

    # Skip any trailing XML tag text (</caps>, </p>, etc.) before address entries.
    # Scan forward up to 100 bytes looking for the first plausible style byte.
    pos = prop_end
    scan_limit = min(pos + 100, len(buf))
    while pos < scan_limit and buf[pos] not in (_NTCP2_ID, _SSU2_ID):
        pos += 1

    max_entries = 20

    while len(addresses) < max_entries and pos + 1 <= len(buf):
        # Peek at this byte — if it's a plausible style (1 or 2), parse entry.
        style_byte = buf[pos]

        if style_byte not in (_NTCP2_ID, _SSU2_ID):
            break  # hit signature or garbage

        entry_start = pos
        pos += 1  # skip style

        # IP address — try v4 first (4 bytes), then v6 (16 bytes)
        # i2pd uses boost::asio::ip::address_v4/v6. The caps byte later tells us.
        # We need to look ahead enough to find the port/date/caps triplet
        # that anchors our offset math.  Instead, try both sizes.
        ip_bytes_count = None
        for ip_len in (4, 16):
            ip_pos = pos
            s_pos = ip_pos + ip_len           # Tag<32> 's'
            i_pos = s_pos + 32                # Tag<32> 'i'
            port_pos = i_pos + 32             # uint16 port
            date_pos = port_pos + 2           # uint64 date
            caps_pos = date_pos + 8           # uint8 caps

            if caps_pos > len(buf):
                continue

            port, = struct.unpack_from("<H", buf, port_pos)
            created_ms, = struct.unpack_from("<Q", buf, date_pos)
            addr_caps, = struct.unpack_from("!B", buf, caps_pos)

            # Sanity: port in normal range
            if 1 <= port < 65535:
                ip_bytes_count = ip_len
                pos = ip_pos
                break
        else:
            # Couldn't resolve IP length — skip this entry
            break

        # Extract IP string
        ip_str = _bytes_to_ip(buf[pos:pos + ip_bytes_count])
        pos += ip_bytes_count  # done with IP

        # Skip s(32) and i(32)
        pos += 64

        # port
        port, = struct.unpack_from("<H", buf, pos)
        pos += 2

        # date (uint64 LE ms)
        created_at = 0.0
        if pos + 8 <= len(buf):
            created_ms, = struct.unpack_from("<Q", buf, pos)
            created_at = created_ms / 1000.0
            pos += 8

        # caps byte
        addr_caps = 0x00
        if pos + 1 <= len(buf):
            addr_caps = buf[pos]
            pos += 1

        protocol = {
            _NTCP2_ID: "NTCP2",
            _SSU2_ID: "SSU2",
            # Other codes: 3=SSU_EXT, etc. Extend as needed.
        }.get(style_byte, f"UNKNOWN_{style_byte}")

        published = bool(addr_caps & (0x01 if ip_bytes_count == 4 else 0x08)) and bool(addr_caps != 0x04)

        ti = TransportInfo(
            ip=ip_str,
            port=port,
            protocol=protocol,
            published=published,
            created_at=created_at,
        )
        addresses.append(ti)

        # Optional SSUExt: if ssu pointer present (4 bytes LE pointing to data)
        # In practice libi2pd writes 0 for the pointer when there's no SSU ext.
        if pos + 4 <= len(buf):
            ssu_ptr, = struct.unpack_from("<I", buf, pos)
            if ssu_ptr == 0:
                pass  # no SSU ext, continue normal parsing

    return addresses


def _bytes_to_ip(b: bytes) -> str:
    try:
        import ipaddress
        return str(ipaddress.ip_address(b))
    except Exception:
        return "127.0.0.1"


# ── public main parser ────────────────────────────────────────────
def parse_rtr(buf: bytes, *, filename: Optional[str] = None) -> RouterInfo:
    """Parse raw .rtr binary buffer into a RouterInfo dataclass.

    Args:
        buf: Raw binary content of the .rtr file (max 3072 bytes).
        filename: Optional original filename — used to derive ident_hash if present.

    Returns:
        A ``RouterInfo`` populated with as much data as could be extracted.
        Never raises — falls back gracefully on malformed input.
    """
    try:
        info = _do_parse(buf, filename)
        return info
    except Exception as exc:
        logger.warning("parse_rtr failed: %s", exc)
        base64_hash = "0" * 20 if not filename else Path(filename).stem
        raw_hashes = _hash_from_name(base64_hash)
        return RouterInfo(
            ident_hash_hex=raw_hashes or "0" * 40,
            key_type=1,
            file_size=len(buf),
        )


def _do_parse(buf: bytes, filename: Optional[str]) -> RouterInfo:
    if len(buf) > MAX_RI_BUFFER_SIZE:
        logger.warning("Buffer %d bytes exceeds max %d", len(buf), MAX_RI_BUFFER_SIZE)

    # Key type byte
    key_type = buf[0] if len(buf) >= 1 else 1

    # Derive ident_hash from filename (base64 encoded 20-byte hash)
    base64_name = Path(filename).stem if filename else ""
    ident_hash_hex = _hash_from_name(base64_name) or "0" * 40

    pos = 1

    # ── Public key (ElGamal ~256 bytes, ECIES 32 bytes) ───────────
    if key_type == CRYPTO_KEY_TYPE_ELGAMAL:
        # ElGamal public key = two bigints; total size is stored as a uint32 BE
        if pos + 4 <= len(buf):
            pk_len, = struct.unpack_from(">I", buf, pos)
            pos += 4  # skip length prefix
            pos += min(pk_len, MAX_RI_BUFFER_SIZE - pos)  # skip key data
        else:
            pos += _ELGAMAL_PUBKEY_SIZE

    elif key_type == CRYPTO_KEY_TYPE_ECIES:
        pos += 32  # ECIES public key is a single X25519 point (32 bytes)

    # ── Certificate chain ──────────────────────────────────────────
    # Each cert entry: uint32 BE length + data.  Loop while we see valid lengths.
    if pos + 4 <= len(buf):
        cert_len, = struct.unpack_from(">I", buf, pos)
        if 0 < cert_len <= MAX_RI_BUFFER_SIZE - pos - 5:
            pos += 4 + cert_len  # skip one certificate

    # ── Timestamp (uint64 LE — milliseconds since epoch) ───────────
    timestamp = 0.0
    if pos + 8 <= len(buf):
        ms, = struct.unpack_from("<Q", buf, pos)
        timestamp = ms / 1000.0
        pos += 8

    # ── Properties map (XML-style) ─────────────────────────────────
    caps_str = ""
    bw_kbps = 0

    if pos < len(buf):
        try:
            props, p_end = _parse_properties(buf, pos)
            pos = p_end

            # Extract caps string from properties
            for k, v in props.items():
                if "caps" in k.lower():
                    caps_str = v.strip()
                    break

            # Try to find bandwidth — it's stored as a raw uint64 between property tags
            bw_candidate = _extract_bandwidth_raw(buf, pos - 200 if pos > 200 else 0, pos)
            if caps_str:
                caps_bws = {"k": 6, "l": 30, "m": 56, "n": 96, "o": 192, "p": 1280, "x": 4096}
                for ch in caps_str:
                    lower_ch = ch.lower()
                    if lower_ch in caps_bws:
                        bw_kbps = max(bw_kbps, caps_bws[lower_ch])

        except Exception as pe:
            logger.debug("Properties parse error: %s", pe)

    # ── Address entries ────────────────────────────────────────────
    try:
        transports_raw = _parse_addresses(buf, pos)
        transports = tuple(transports_raw)
    except Exception as ae:
        logger.debug("Address parsing error: %s", ae)
        transports = ()

    # ── Options mask (from transport protocols found) ──────────────
    options_mask = 0
    for t in transports:
        cap = addr_caps_from_proto(t.protocol, t.ip.startswith("::"))
        options_mask |= cap

    return RouterInfo(
        ident_hash_hex=ident_hash_hex,
        key_type=key_type,
        version=int(timestamp),
        bandwidth_kbps=bw_kbps,
        transports=transports,
        options_mask=options_mask,
        caps=caps_str,
        published=bool(options_mask & 0x01),  # has a public IPv4 transport
        file_size=len(buf),
    )


def addr_caps_from_proto(protocol: str, is_v6: bool) -> int:
    """Map (protocol, ipv6) → models.Transport bitmask."""
    mapping: dict[tuple[str, bool], int] = {
        ("NTCP2", False): 0x01,   # NTCP2V4
        ("NTCP2", True): 0x02,    # NTCP2V6
        ("SSU2", False): 0x04,    # SSU2V4
        ("SSU2", True): 0x08,     # SSU2V6
    }
    return mapping.get((protocol, is_v6), 0)


def _hash_from_name(b64name: str) -> Optional[str]:
    """Decode a base64 filename stem to hex of the raw 20-byte hash."""
    if not b64name:
        return None
    try:
        padded = b64name + "=" * (-len(b64name) % 4)
        raw = base64.b64decode(padded, altchars=b"-_")
        if len(raw) == 20:
            return raw.hex()
    except Exception:
        pass
    try:
        padded = b64name + "=" * (-len(b64name) % 4)
        raw = base64.urlsafe_b64decode(padded)
        if len(raw) == 20:
            return raw.hex()
    except Exception:
        pass
    return None


def parse_rtr_file(filepath: str | Path) -> Optional[RouterInfo]:
    """Read and parse a single .rtr file. Returns None on I/O failure."""
    try:
        buf = Path(filepath).read_bytes()
        return parse_rtr(buf, filename=str(filepath))
    except Exception as exc:
        logger.warning("Cannot read %s: %s", filepath, exc)
        return None
