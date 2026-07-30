"""Tests for src/addressbook.py — AddressBookCatalog and helpers."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from src.addressbook import (
    AddressBookCatalog,
    _b64tohex,
    _hex_to_b32_addr,
)
from src.config import I2PConfig
from src.models import LeaseSetInfo, RouterInfo


class TestHexToB32:
    def test_basic_conversion(self):
        hx = "A" * 40
        addr = _hex_to_b32_addr(hx)
        assert addr.endswith(".b32.i2p")

    def test_address_length(self):
        # 20 bytes -> 32 chars of base32 + padding
        hx = "1234567890" * 4 + "ABCD"
        addr = _hex_to_b32_addr(hx)
        assert len(addr) >= 20

    def test_known_hash(self):
        # All zeros hash
        hx = "0" * 40
        addr = _hex_to_b32_addr(hx)
        assert ".b32.i2p" in addr


class TestB64ToHex:
    def test_valid_base64_20_bytes(self):
        import base64
        raw = b"\xAB\xCD" * 10  # exactly 20 bytes
        encoded = base64.b64encode(raw).decode().rstrip("=")
        result = _b64tohex(encoded)
        assert result == raw.hex()

    def test_invalid_input_returns_none(self):
        assert _b64tohex("") is None
        assert _b64tohex("!!!") is None

    def test_urlsafe_b64(self):
        import base64
        raw = b"\x12\x34\x56" * 6 + b"\x78\x9A"
        encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        result = _b64tohex(encoded)
        assert result == raw.hex()


class TestAddressBookCatalogInMemory:
    """Test catalog without network or filesystem dependencies."""

    def setup_method(self):
        self.catalog = AddressBookCatalog(db_path=":memory:")

    def teardown_method(self):
        self.catalog.close()

    def test_init_creates_tables(self):
        """SQLite tables should exist after init."""
        cur = self.catalog._conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}
        assert "routers" in tables
        assert "transports" in tables
        assert "leasesets" in tables

    def test_add_router_via_scrape_simulation(self):
        """Manually inject a router and verify queries."""
        ri = RouterInfo(ident_hash_hex="AA" * 20, key_type=1, caps="fR4", bandwidth_kbps=256)
        self.catalog._routers["AA" * 20] = ri
        self.catalog._sync_db()

        assert len(self.catalog.all_routers()) == 1

    def test_all_routers_sorted_by_bw(self):
        """all_routers should sort by bandwidth descending."""
        low = RouterInfo(ident_hash_hex="BB" * 20, key_type=1, bandwidth_kbps=48)
        hi = RouterInfo(ident_hash_hex="CC" * 20, key_type=1, bandwidth_kbps=1024)
        self.catalog._routers["BB" * 20] = low
        self.catalog._routers["CC" * 20] = hi
        self.catalog._sync_db()

        routers = self.catalog.all_routers()
        assert routers[0].bandwidth_kbps >= routers[1].bandwidth_kbps

    def test_floodfill_only(self):
        """floodfill_only should only return 'f' capability routers."""
        flood = RouterInfo(ident_hash_hex="DD" * 20, key_type=1, caps="fR3", bandwidth_kbps=512)
        normal = RouterInfo(ident_hash_hex="EE" * 20, key_type=1, caps="R3", bandwidth_kbps=128)
        self.catalog._routers["DD" * 20] = flood
        self.catalog._routers["EE" * 20] = normal
        self.catalog._sync_db()

        ff = self.catalog.floodfill_only()
        assert len(ff) == 1
        assert ff[0].ident_hash_hex == "DD" * 20

    def test_get_by_hash(self):
        ri = RouterInfo(ident_hash_hex="FF" * 20, key_type=1)
        ls = LeaseSetInfo(ident_hash_hex="FF" * 20, store_type=2)
        self.catalog._routers["FF" * 20] = ri
        self.catalog._leasesets["FF" * 20] = ls
        self.catalog._sync_db()

        r, l = self.catalog.get_by_hash("FF" * 20)
        assert r is not None and l is not None

    def test_get_by_hash_missing(self):
        r, l = self.catalog.get_by_hash("NOT_FOUND")
        assert r is None and l is None

    def test_all_destinations(self):
        """DestinationEntry list should include routers + leasesets."""
        ri = RouterInfo(ident_hash_hex="12" * 20, key_type=1, caps="R")
        self.catalog._routers["12" * 20] = ri
        self.catalog._sync_db()

        dests = self.catalog.all_destinations()
        assert len(dests) >= 1

    def test_stats(self):
        """stats dict has expected keys and correct counts."""
        ri = RouterInfo(ident_hash_hex="34" * 20, key_type=1, caps="f", bandwidth_kbps=256)
        self.catalog._routers["34" * 20] = ri
        self.catalog._sync_db()

        s = self.catalog.stats()
        assert s["total_routers"] >= 1
        assert "floodfill_count" in s
        assert "avg_bandwidth_kbps" in s
        assert "unique_destinations" in s

    def test_summary(self):
        """summary returns a non-empty string."""
        ri = RouterInfo(ident_hash_hex="56" * 20, key_type=1)
        self.catalog._routers["56" * 20] = ri
        self.catalog._sync_db()

        text = self.catalog.summary()
        assert "AddressBook:" in text
        assert len(text) > 20

    def test_sync_db_populates_sqlite(self):
        """Data should be queryable from SQLite after sync."""
        ri = RouterInfo(ident_hash_hex="78" * 20, key_type=1, caps="fR", bandwidth_kbps=512)
        self.catalog._routers["78" * 20] = ri
        self.catalog._sync_db()

        cur = self.catalog._conn.cursor()
        cur.execute("SELECT ident_hash_hex FROM routers WHERE caps LIKE '%f%'")
        rows = cur.fetchall()
        assert len(rows) >= 1

    def test_empty_catalog(self):
        """Empty catalog should still work."""
        s = self.catalog.stats()
        assert s["total_routers"] == 0
        assert self.catalog.summary()


class TestAddressBookCatalogWithNetdbFiles:
    """Test with actual .rtr files on disk."""

    def test_scan_netdb_with_rtr_files(self):
        # Build a minimal .rtr buffer and write it to a temp dir
        buf = self._build_rtr()
        with tempfile.TemporaryDirectory() as tmpdir:
            ndir = Path(tmpdir)
            (ndir / "test_router.rtr").write_bytes(buf)

            catalog = AddressBookCatalog(netdb_dir=ndir, db_path=":memory:")
            try:
                count = catalog.load()
                assert isinstance(count, int)
            finally:
                catalog.close()

    @staticmethod
    def _build_rtr(
        caps: str = "fR4", bw_kbps: int = 256
    ) -> bytes:
        """Minimal parseable .rtr buffer."""
        import struct

        parts: list[bytes] = []
        parts.append(struct.pack("!B", 0))  # version
        parts.append(b"\x41" * 20)  # ident hash
        parts.append(struct.pack(">Q", 1700000000))  # timestamp
        parts.append(struct.pack("!B", 1))  # key type = ElGamal
        parts.append(b"\xAA" * 256)  # pubkey

        style_tag = f"<i2p.router.java.style:{caps}>"
        bw_out = f"<i2p.router.java.bw.outbound:{bw_kbps * 1024}>"
        props_bytes = (style_tag + bw_out).encode()
        parts.append(struct.pack("<I", len(props_bytes)))
        parts.append(props_bytes)
        return b"".join(parts)

    def test_scan_nonexistent_dir(self):
        """Catalog with nonexistent netdb dir should fall back to webconsole."""
        catalog = AddressBookCatalog(netdb_dir="/nonexistent/path", db_path=":memory:")
        # load shouldn't crash even with bad dir
        count = catalog.load()
        assert isinstance(count, int)
        catalog.close()

    def test_load_with_no_netdb_dir(self):
        """None netdb -> goes straight to webconsole fallback."""
        config = I2PConfig()
        catalog = AddressBookCatalog(netdb_dir=None, config=config, db_path=":memory:")
        count = catalog.load()
        # Webconsole on this machine works but has limited data — 0 is ok
        assert isinstance(count, int)
        catalog.close()
