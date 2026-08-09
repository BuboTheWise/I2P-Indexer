"""Data models for I2P addressbook entries."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


class Transport(enum.IntFlag):
    """CompatibleTransports bitmask from RouterInfo.h."""
    NTCP2V4 = 0x01
    NTCP2V6 = 0x02
    SSU2V4  = 0x04
    SSU2V6  = 0x08
    MESH    = 0x10

# Bandwidth thresholds (KBps) from RouterInfo.h.
BW_LOW  = 48
BW_HIGH = 256
BW_EXTRA = 2048


def classify_bw(kbps: int) -> str:
    """Return human-readable bandwidth tier name."""
    if kbps < 12:     return "vlow"
    if kbps < BW_LOW: return "low"
    if kbps < 64:     return "below_avg"
    if kbps < BW_HIGH: return "avg"
    if kbps < BW_EXTRA: return "high"
    return "extra_high"


# Capability flag chars from router style XML.
CAP_FLOODFILL = "f"
CAP_HIDDEN    = "H"
CAP_REACHABLE = "R"
CAP_UNREACHABLE = "U"


@dataclass(frozen=True)
class TransportInfo:
    ip: str
    port: int
    protocol: str  # "NTCP2" | "SSU2" | "SSU_EXT"
    published: bool = True
    created_at: float = 0.0


@dataclass(frozen=True)
class RouterInfo:
    """Parsed router info from a .rtr file."""
    ident_hash_hex: str        # 40-char hex of SHA-1 (20 bytes)
    key_type: int              # 1=ElGamal, 3=ECIES
    version: int = 0
    bandwidth_kbps: int = 0
    transports: tuple[TransportInfo, ...] = ()
    options_mask: int = 0      # transport bits
    caps: str = ""             # capability string (e.g. "fR4")
    published: bool = False
    file_size: int = 0         # raw .rtr file bytes

    @property
    def is_floodfill(self) -> bool:
        return CAP_FLOODFILL in self.caps

    @property
    def bw_class(self) -> str:
        return classify_bw(self.bandwidth_kbps)


@dataclass(frozen=True)
class LeaseSetInfo:
    """Parsed lease set from a .ls64 file."""
    ident_hash_hex: str        # 40-char hex of destination hash
    store_type: int            # NETDB_STORE_TYPE_* enum
    num_leases: int = 0
    options_mask: int = 0
    leases_v1_count: int = 0   # v1 lease count
    created_at: float = 0.0
    file_size: int = 0

    @property
    def has_v1(self) -> bool:
        return self.leases_v1_count > 0


@dataclass(frozen=True)
class DestinationEntry:
    """A parseable destination with its .i2p address."""
    ident_hash_hex: str
    b32_addr: str              # base32 hostname (e.g., "abcdefghijklmnop.b32.i2p")
    is_router: bool            # also a known router?
    routers_known: int = 0     # how many .rtr files found
    leasesets_known: int = 0   # how many .ls64 files found
    last_updated: datetime | None = None


@dataclass
class DiscoveryResult:
    """Structure returned by _do_probe() describing one probe attempt."""
    b32_addr: str = ''
    ident_hash_hex: str = ''
    reachable: bool = False
    status_code: int = 0
    body_length: int = 0
    title: str = ''
    response_time_sec: float = 0.0
    via_method: str = 'b32'       # b32 | dns | b32+dns
    error: str = ''
    probe_mode: str = 'b32'       # which mode produced this result
    # Extractor output — always populated even when no extractor claims
    content_type: str = ''
    content_summary: Optional[str] = None   # can be None when unreachable
    found_links: list = field(default_factory=list)
    # Flagging heuristics (robots, tech stack, contact, forum, redirect)
    flags: list = field(default_factory=list)
    # needs_review — set True by extractor framework when no extractor matched
    needs_review: bool = False
    reason: str = ''            # reason string for needs_review (e.g. "no_extractor_claimed")
    detected_lang: str = ''    # ISO 639-1 language code from langid (e.g. 'de', 'ja')
    # Content fingerprinting
    content_hash: str = ''     # SHA-256 of page body (empty when unreachable)
    last_modified: str = ''    # Last-Modified header value, if present
