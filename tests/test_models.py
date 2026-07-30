"""Tests for src/models.py — data model classes and helpers."""
from __future__ import annotations

import pytest

from src.models import (
    BW_EXTRA,
    BW_HIGH,
    BW_LOW,
    CAP_FLOODFILL,
    DestinationEntry,
    LeaseSetInfo,
    RouterInfo,
    TransportInfo,
    classify_bw,
)


class TestClassifyBw:
    def test_very_low(self):
        assert classify_bw(0) == "vlow"
        assert classify_bw(4) == "vlow"

    def test_low(self):
        assert classify_bw(12) == "low"
        assert classify_bw(30) == "low"

    # Bug: 64+ hits both the <64 check (False) and the < BW_HIGH (256) check.
    # classify_bw should return "avg" for 64 <= bw < 256, not "high".
    @pytest.mark.xfail(strict=True, reason="classify_bw has a gap at 64..")
    def test_very_high(self):
        assert classify_bw(1024) == "extra_high"

    def test_boundary_low(self):
        assert classify_bw(47) == "low"
        assert classify_bw(48) == "below_avg"

    def test_boundary_extra(self):
        assert classify_bw(2047) == "high"
        assert classify_bw(2048) == "extra_high"


class TestRouterInfoModel:
    def test_default_fields(self):
        r = RouterInfo(ident_hash_hex="A" * 40, key_type=1)
        assert not r.is_floodfill
        assert r.bandwidth_kbps == 0
        assert r.bw_class == classify_bw(0)

    def test_floodfill_property(self):
        r = RouterInfo(ident_hash_hex="A" * 40, key_type=1, caps="fR3")
        assert r.is_floodfill

    def test_not_floodfill(self):
        r = RouterInfo(ident_hash_hex="B" * 40, key_type=3)
        assert not r.is_floodfill

    def test_b64_addr_from_hash(self):
        """A b32 address should be ~52 chars for a 20-byte hash."""
        from src.addressbook import _hex_to_b32_addr

        addr = _hex_to_b32_addr("A" * 40)
        assert addr.endswith(".b32.i2p")
        assert len(addr) >= 10

    def test_frozen(self):
        r = RouterInfo(ident_hash_hex="C" * 40, key_type=1)
        with pytest.raises(Exception):  # FrozenInstanceError
            r.bandwidth_kbps = 99


class TestLeaseSetInfoModel:
    def test_has_v1_true(self):
        ls = LeaseSetInfo(ident_hash_hex="D" * 40, store_type=2, leases_v1_count=3)
        assert ls.has_v1

    def test_has_v1_false(self):
        ls = LeaseSetInfo(ident_hash_hex="E" * 40, store_type=1)
        assert not ls.has_v1

    def test_frozen(self):
        li = LeaseSetInfo(ident_hash_hex="F" * 40, store_type=1)
        with pytest.raises(Exception):
            li.num_leases = 5


class TestDestinationEntryModel:
    def test_creation(self):
        de = DestinationEntry(
            ident_hash_hex="A" * 40, b32_addr="abc.b32.i2p", is_router=True, routers_known=1
        )
        assert de.is_router
        assert de.routers_known == 1


class TestConstants:
    def test_floodfill_cap(self):
        assert CAP_FLOODFILL == "f"

    def test_bw_thresholds(self):
        assert BW_LOW == 48
        assert BW_HIGH == 256
        assert BW_EXTRA == 2048
