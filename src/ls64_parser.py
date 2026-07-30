"""Binary parser for i2pd .ls64 (LeaseSet) files.

Struct-based parsing of the LeaseSet buffer format defined in libi2pd/
LeaseSet.cpp / LeaseSet.h.  Returns partial data on malformed input.
"""
from __future__ import annotations

import base64
import logging
import struct
from pathlib import Path
from typing import Optional

from src.models import LeaseSetInfo

logger = logging.getLogger(__name__)

MAX_LS_BUFFER_SIZE = 3072

# Store type constants from libi2pd/netdb/NetDb.h
STORE_UNKNOWN  = 0x01
STORE_ROUTER   = 0x02
STORE_DESTINATION = 0x04


def _read_u16_be(buf: bytes, off: int) -> tuple[int, int]:
    v, = struct.unpack_from(">H", buf, off)
    return v, off + 2


def _read_u32_be(buf: bytes, off: int) -> tuple[int, int]:
    v, = struct.unpack_from(">I", buf, off)
    return v, off + 4


def _read_u64_le(buf: bytes, off: int) -> tuple[int, int]:
    v, = struct.unpack_from("<Q", buf, off)
    return v, off + 8


def parse_ls64(buf: bytes, *, filename: Optional[str] = None) -> LeaseSetInfo:
    """Parse raw .ls64 binary buffer into a LeaseSetInfo dataclass.

    The .ls64 file content is base64-encoded on disk; decode first if needed,
    then parse the binary LeaseSet structure.

    Binary layout (simplified):
      store_type(1) + hash(20) + timestamp(8 LE) +
      version(1) + options_mask(2 BE) +
      lease_count(2 BE) + leases[...] +
      [v1_lease_count(2 BE)] + v1_leases[...] +
      signature

    Each lease (v2):
      gw_hash(20) + session_data(tag 4 + data_len 2 + data) +
      encryption_key(32) + hmac_key(32) + expiration(8 LE)

    Each lease (v1):
      dest_tag(4) + enc_key(192) + sign(64) + port(2 BE) +
      ident_hash(20) + created(4 BE) + lifetime(4 BE) + style(2 BE) +
      ip_or_tag(4)

    Args:
        buf: Raw file content (may be base64 or already decoded).
        filename: Used to derive ident_hash via b64 decode.

    Returns:
        Populated LeaseSetInfo, never raises.
    """
    try:
        return _do_parse_ls64(buf, filename)
    except Exception as exc:
        logger.warning("parse_ls64 failed: %s", exc)
        hex_hash = _hash_from_name(Path(filename).stem if filename else "") or "0" * 40
        return LeaseSetInfo(
            ident_hash_hex=hex_hash,
            store_type=STORE_UNKNOWN,
            file_size=len(buf),
        )


def _do_parse_ls64(buf: bytes, filename: Optional[str]) -> LeaseSetInfo:
    """Core parsing logic."""

    # If buf looks like base64 (text with line breaks + == padding), decode it.
    if len(buf) > 0 and all(b in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r\t " for b in buf[:min(100, len(buf))]):
        try:
            decoded = base64.b64decode(buf)
            if isinstance(decoded, bytes) and 20 <= len(decoded) <= MAX_LS_BUFFER_SIZE:
                buf = decoded
        except Exception:
            pass  # treat as raw binary

    pos = 0

    # Store type byte
    store_type = buf[pos] if pos < len(buf) else STORE_UNKNOWN
    pos += 1

    # Hash (20 bytes — destination hash)
    hash_hex = "0" * 40
    if pos + 20 <= len(buf):
        hash_hex = buf[pos:pos + 20].hex()
        pos += 20

    # Fallback: derive from filename if we couldn't read it from buffer
    if hash_hex == "0" * 40 and filename:
        fallback = _hash_from_name(Path(filename).stem)
        if fallback:
            hash_hex = fallback

    # Timestamp (uint64 LE ms since epoch)
    timestamp = 0.0
    if pos + 8 <= len(buf):
        ts_ms, = struct.unpack_from("<Q", buf, pos)
        timestamp = ts_ms / 1000.0
        pos += 8

    # Version byte (optional in some implementations)
    version = 0
    if pos < len(buf):
        version = buf[pos]
        pos += 1

    # Options mask (uint16 BE)
    options_mask = 0
    if pos + 2 <= len(buf):
        options_mask, pos = _read_u16_be(buf, pos)

    # ── V2 leases ────────────────────────────────────────────────
    num_leases = 0
    v2_pos = pos

    if pos + 2 <= len(buf):
        lease_count, _ = _read_u16_be(buf, pos)
        pos += 2

        remaining = len(buf) - pos
        parsed_v2 = 0

        for idx in range(lease_count):
            # Minimum v2 lease: gw_hash(20) + session(tag4+len2) + enc_key(32) + hmac(32) + exp(8) = ~100B
            if pos >= len(buf):
                break

            gw_hash_pos = pos
            pos += 20  # gateway ident hash

            # Session data: tag(4) + length_prefix or direct data
            if pos + 6 > len(buf):
                break
            pos += 4  # session tag
            try:
                sess_len, = struct.unpack_from(">H", buf, pos)
                pos += 2
                pos = min(pos + sess_len, len(buf))
            except Exception:
                pos += 1

            # Encryption key + HMAC
            pos = min(pos + 32 + 32, len(buf))

            # Expiration (uint64 LE)
            if pos + 8 <= len(buf):
                _, = struct.unpack_from("<Q", buf, pos)
                pos += 8

            parsed_v2 += 1

        num_leases = parsed_v2

    # ── V1 leases (optional block that follows v2) ───────────────
    leases_v1_count = 0

    if pos + 2 <= len(buf):
        # Peek: does this look like a sensible v1 count?
        maybe_count, _ = _read_u16_be(buf, pos)
        if maybe_count > 0 and maybe_count < 50:
            pos += 2

            for idx in range(maybe_count):
                # v1 lease layout (from LeaseSet::addLease v1 handling):
                # dest_tag(4) + enc_key(192-32=160 ElGamal) + sign(64-32=32 ECDSA)
                #   or simply: tag(4) + data(varies based on version byte above)
                # v1 lease in i2pd binary ≈ ~80-150 bytes each.
                if pos >= len(buf):
                    break

                # Minimal v1: dest_tag(4) + enc_key(32) + sign_key(32) + port(2) + ident(20)
                #   + created(4) + lifetime(4) + style(2) + IP_or_tag(4) = ~104
                min_v1 = 4 + 32 + 32 + 2 + 20 + 4 + 4 + 2 + 4
                if pos + min_v1 > len(buf):
                    break

                pos += min_v1
                leases_v1_count += 1

    return LeaseSetInfo(
        ident_hash_hex=hash_hex,
        store_type=store_type,
        num_leases=num_leases,
        options_mask=options_mask,
        leases_v1_count=leases_v1_count,
        created_at=timestamp,
        file_size=len(buf),
    )


def parse_ls64_file(filepath: str | Path) -> Optional[LeaseSetInfo]:
    """Read and parse a single .ls64 file. Returns None on I/O failure."""
    try:
        buf = Path(filepath).read_bytes()
        return parse_ls64(buf, filename=str(filepath))
    except Exception as exc:
        logger.warning("Cannot read %s: %s", filepath, exc)
        return None


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
