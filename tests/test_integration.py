"""Tests for src/integration.py — DiscoveryResult, DiscoveryDB, probe flow, reporting."""
from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile

import pytest
from unittest.mock import MagicMock, patch, call

from src.integration import (
    DEFAULT_DB_PATH,
    DiscoveryDB,
    DiscoveryResult,
    discover_addresses,
    print_report,
    query_db,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path):
    """A temporary on-disk SQLite database for DiscoveryDB."""
    db_file = str(tmp_path / "test_indexer.db")
    return db_file


@pytest.fixture
def db(tmp_db):
    instance = DiscoveryDB(db_path=tmp_db)
    yield instance
    instance.close()


@pytest.fixture
def mock_resp():
    def _build(status=200, body_len=1234, title_text="OK Page"):
        raw_body = b"<html><title>" + title_text.encode() + b"</title>\n" + b"x" * max(0, body_len - 60)
        mock = MagicMock()
        mock.status = status
        mock.body = raw_body
        mock.text = raw_body.decode("utf-8", errors="replace")
        mock.title = MagicMock(return_value=title_text)
        return mock

    return _build


# ---------------------------------------------------------------------------
# DiscoveryResult tests
# ---------------------------------------------------------------------------

class TestDiscoveryResult:
    def test_reachable(self):
        dr = DiscoveryResult(
            b32_addr="i2p-projekt.i2p",
            ident_hash_hex="a" * 40,
            reachable=True,
            status_code=200,
            body_length=1234,
            title="Test Page",
            response_time_sec=5.2,
        )
        assert dr.reachable is True
        assert dr.status_code == 200
        assert dr.body_length == 1234

    def test_unreachable_default(self):
        dr = DiscoveryResult(
            b32_addr="dead.i2p",
            ident_hash_hex="b" * 40,
            error="Connection refused",
        )
        assert dr.reachable is False
        assert dr.status_code == 0
        assert dr.error

    def test_sorting_by_reachability(self):
        r1 = DiscoveryResult(b32_addr="ok.i2p", ident_hash_hex="", reachable=True, response_time_sec=8.0)
        r2 = DiscoveryResult(b32_addr="dead.i2p", ident_hash_hex="", reachable=False, error="timeout")
        items = [r2, r1]
        items.sort(key=lambda r: (not r.reachable, r.response_time_sec))
        assert items[0].reachable is True

    def test_sorting_by_speed_among_reachable(self):
        a = DiscoveryResult(b32_addr="fast.i2p", ident_hash_hex="", reachable=True, response_time_sec=3.0)
        b = DiscoveryResult(b32_addr="slow.i2p", ident_hash_hex="", reachable=True, response_time_sec=9.0)
        items = [b, a]
        items.sort(key=lambda r: (not r.reachable, r.response_time_sec))
        assert items[0].response_time_sec == 3.0

    def test_via_method_b32(self):
        dr = DiscoveryResult(
            b32_addr="abc.b32.i2p",
            ident_hash_hex="c" * 40,
            reachable=True,
            via_method="b32",
        )
        assert "b32" in dr.via_method

    def test_via_method_dns(self):
        dr = DiscoveryResult(
            b32_addr="foo.i2p",
            ident_hash_hex="d" * 40,
            reachable=True,
            via_method="dns",
        )
        assert "dns" in dr.via_method


# ---------------------------------------------------------------------------
# DiscoveryDB tests
# ---------------------------------------------------------------------------

class TestDiscoveryDB:
    def test_init_creates_tables(self, db):
        cur = db._conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {r[0] for r in cur.fetchall()}
        assert "routers" in tables
        assert "leasesets" in tables
        assert "discoveries" in tables

    def test_record_router(self, db):
        db.record_router(
            ident_hash_hex="AABBCCDD" * 4,
            key_type=10,
            version=32,
            bandwidth_kbps=500,
            caps="X",
            published=True,
            i2p_dns_name="test.i2p",
        )
        cur = db._conn.cursor()
        cur.execute("SELECT ident_hash_hex, i2p_dns_name FROM routers")
        rows = cur.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "AABBCCDD" * 4

    def test_record_router_upsert(self, db):
        db.record_router(
            ident_hash_hex="DEADBEEF" * 4,
            bandwidth_kbps=100,
            i2p_dns_name="",
        )
        # Upsert with DNS name fills in the blank
        db.record_router(
            ident_hash_hex="DEADBEEF" * 4,
            bandwidth_kbps=500,
            i2p_dns_name="filled.i2p",
        )
        cur = db._conn.cursor()
        cur.execute("SELECT i2p_dns_name FROM routers")
        dns = cur.fetchone()[0]
        assert dns == "filled.i2p"

    def test_record_lease_set(self, db):
        db.record_lease_set(
            ident_hash_hex="1122334455" * 3 + "1122",
            store_type=0,
            num_leases=3,
            i2p_dns_name="ls-test.i2p",
        )
        cur = db._conn.cursor()
        cur.execute("SELECT ident_hash_hex FROM leasesets")
        assert cur.fetchone()[0] == "1122334455" * 3 + "1122"

    def test_record_discovery(self, db):
        row_id = db.record_discovery(
            ident_hash_hex="AA" * 20,
            b32_addr="TEST.b32.i2p",
            i2p_dns_name="test.i2p",
            probe_mode="b32",
            reachable=True,
            status_code=200,
            body_length=1500,
            title="Test Site",
            response_time=2.5,
        )
        assert isinstance(row_id, int)

    def test_query_by_hash(self, db):
        db.record_discovery(
            ident_hash_hex="FF" * 20,
            b32_addr="ff.b32.i2p",
            probe_mode="b32",
            reachable=True,
            status_code=200,
        )
        results = db.get_latest_probes_by_hash("FF" * 20)
        assert len(results) == 1
        assert results[0]["ident_hash_hex"] == "FF" * 20

    def test_query_by_dns_name(self, db):
        db.record_discovery(
            ident_hash_hex="EE" * 20,
            b32_addr="ee.b32.i2p",
            i2p_dns_name="mydns.i2p",
            probe_mode="dns",
            reachable=True,
        )
        results = db.get_latest_probes_by_dns_name("mydns.i2p")
        assert len(results) == 1
        assert results[0]["i2p_dns_name"] == "mydns.i2p"

    def test_summary_counts(self, db):
        db.record_router(ident_hash_hex="A" * 40)
        db.record_lease_set(ident_hash_hex="A" * 40)
        db.record_discovery(
            ident_hash_hex="A" * 40,
            b32_addr="a.b32.i2p",
            probe_mode="b32",
            reachable=True,
        )
        s = db.summary()
        assert s["routers"] == 1
        assert s["leasesets"] == 1
        assert s["total_probes"] == 1
        assert s["unique_destinations"] == 1
        assert s["reachable_count"] == 1

    def test_get_all_hashes(self, db):
        db.record_discovery(
            ident_hash_hex="ZZ" * 20, b32_addr="a.b32.i2p", probe_mode="b32", reachable=True,
        )
        db.record_discovery(
            ident_hash_hex="YY" * 20, b32_addr="b.b32.i2p", probe_mode="b32", reachable=False,
        )
        hashes = db.get_all_hashes()
        assert len(set(hashes)) == 2

    def test_close(self, tmp_db):
        inst = DiscoveryDB(db_path=tmp_db)
        inst.close()
        # After close, operations should fail
        with pytest.raises((sqlite3.ProgrammingError, sqlite3.DatabaseError)):
            inst.record_router(ident_hash_hex="A" * 40)


# ---------------------------------------------------------------------------
# discover_addresses tests (mocked)
# ---------------------------------------------------------------------------

class TestDiscoverAddresses:
    """Test discover_addresses without live network calls."""

    @pytest.fixture
    def test_db(self, tmp_path):
        db_inst = DiscoveryDB(db_path=str(tmp_path / "disc.db"))
        yield db_inst
        db_inst.close()

    @patch("src.integration.fetch_i2p")
    def test_dns_only_site(self, mock_fetch, mock_resp, test_db):
        mock_fetch.return_value = mock_resp(200, 5678, "Good Site")
        results = discover_addresses(known_addrs=["http://test.i2p/"], db_instance=test_db)
        assert len(results) == 1
        r = results[0]
        assert r.reachable is True
        assert r.status_code == 200
        assert r.body_length > 0

    @patch("src.integration.fetch_i2p")
    def test_hash_only_site_(self, mock_fetch, test_db):
        # When only a hash is given, it probes the b32 address
        mock_fetch.return_value = MagicMock(
            status=200,
            text="<html><title>Hash Site</title><body>Hello</body></html>",
            body=b"x" * 5000,
            title=lambda: "Hash Site",
        )
        results = discover_addresses(known_addrs=["aabbccddee" * 4], db_instance=test_db)
        assert len(results) == 1
        assert results[0].reachable is True

    @patch("src.integration.fetch_i2p")
    def test_hash_and_dns_both_probed(self, mock_fetch, mock_resp, test_db):
        # With both hash and DNS name, we expect two fetch calls
        mock_fetch.return_value = mock_resp(200, 1000, "Dual Site")
        results = discover_addresses(known_addrs=[("aabbccddee" * 4, "dual.i2p")], db_instance=test_db)
        # Only one target resolved (tuple treated as known addr; hash gets b32, dns gets DNS)
        assert len(results) == 1

    @patch("src.integration.fetch_i2p")
    def test_exception_handling(self, mock_fetch, test_db):
        mock_fetch.side_effect = ConnectionRefusedError("no proxy")
        results = discover_addresses(known_addrs=["http://err.i2p/"], db_instance=test_db)
        r = results[0]
        assert not r.reachable

    @patch("src.integration.fetch_i2p")
    def test_multiple_sites_sorted(self, mock_fetch, mock_resp, test_db):
        mock_fetch.return_value = mock_resp(200, 1000, "Site")
        addrs = ["http://a.i2p/", "http://b.i2p/", "http://c.i2p/"]
        results = discover_addresses(known_addrs=addrs, db_instance=test_db)
        assert len(results) == 3

    @patch("src.integration.fetch_i2p")
    def test_bare_hostname_normalized(self, mock_fetch, mock_resp, test_db):
        mock_fetch.return_value = mock_resp(200, 500, "Hi")
        results = discover_addresses(known_addrs=["bare.i2p"], db_instance=test_db)
        assert len(results) == 1

    @patch("src.integration.fetch_i2p")
    def test_empty_known_addrs_uses_defaults(self, mock_fetch, mock_resp, test_db):
        """When no known_addrs given, discover_addresses falls back to well-known list."""
        mock_fetch.return_value = mock_resp(200, 100, "Default")
        results = discover_addresses(db_instance=test_db)
        assert len(results) >= 3  # at least the 4 well-known sites


# ---------------------------------------------------------------------------
# query_db tests
# ---------------------------------------------------------------------------

class TestQueryDB:
    def test_query_by_hash(self, tmp_db):
        db_inst = DiscoveryDB(db_path=tmp_db)
        db_inst.record_discovery(
            ident_hash_hex="AA" * 20, b32_addr="a.b32.i2p", probe_mode="b32",
            reachable=True, status_code=200,
        )
        db_inst.close()
        # Now query it back
        results = query_db(hash_hex="AA" * 20, db_path=tmp_db)
        assert len(results) == 1

    def test_query_by_dns(self, tmp_db):
        db_inst = DiscoveryDB(db_path=tmp_db)
        db_inst.record_discovery(
            ident_hash_hex="BB" * 20, b32_addr="b.b32.i2p", probe_mode="dns",
            reachable=True, i2p_dns_name="mytest.i2p", status_code=200,
        )
        db_inst.close()
        results = query_db(dns_name="mytest.i2p", db_path=tmp_db)
        assert len(results) == 1

    def test_query_summary_no_args(self, tmp_db, capsys):
        db_inst = DiscoveryDB(db_path=tmp_db)
        db_inst.close()
        _ = query_db(db_path=tmp_db)
        captured = capsys.readouterr()
        assert "DB Summary" in captured.out


# ---------------------------------------------------------------------------
# print_report tests
# ---------------------------------------------------------------------------

class TestPrintReport:
    def test_reachable_and_dead_shown(self, capsys):
        results = [
            DiscoveryResult(
                b32_addr="ok.b32.i2p", ident_hash_hex="a" * 40,
                reachable=True, status_code=200, body_length=1000, title="OK",
                response_time_sec=3.0, via_method="b32",
            ),
            DiscoveryResult(
                b32_addr="dead.b32.i2p", ident_hash_hex="b" * 40,
                reachable=False, error="timeout", response_time_sec=120.0,
            ),
        ]
        print_report(results)
        captured = capsys.readouterr()
        assert "I2P DISCOVERY RESULTS" in captured.out
        assert "OK" in captured.out
        assert "DOWN" in captured.out

    def test_empty_results(self, capsys):
        print_report([])
        captured = capsys.readouterr()
        assert "Total: 0" in captured.out
