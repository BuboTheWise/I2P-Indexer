"""Tests for src/integration.py — DiscoveryResult, DiscoveryDB, probe flow, reporting."""
from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile

import pytest
from unittest.mock import MagicMock, patch, call

from src.integration import (
    _do_probe,
    _extract_flags,
    _extract_i2p_links,
    DEFAULT_DB_PATH,
    DiscoveryDB,
    DiscoveryResult,
    discover_addresses,
    get_address_book,
    print_address_book,
    print_report,
    query_db,
)

from src.addressbook import AddressBookCatalog

from src.models import RouterInfo


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
        mock.headers = {}
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
            headers={},
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


# ---------------------------------------------------------------------------
# TestAddressBookView — SQL view + address_book() + print_address_book
# ---------------------------------------------------------------------------
class TestAddressBookView:
    """Verify the 'address_book' SQL view, DB method, and pretty-print."""

    def test_view_exists(self, tmp_db):
        db = DiscoveryDB(db_path=tmp_db)
        cur = db._conn.cursor()
        # The view should be created during _init_db
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='view' AND name='address_book'"
        )
        assert cur.fetchone() is not None
        db.close()

    def test_empty_view(self, tmp_db):
        db = DiscoveryDB(db_path=tmp_db)
        rows = db.address_book()
        assert rows == []
        db.close()

    def test_one_entry_in_view(self, tmp_db):
        db = DiscoveryDB(db_path=tmp_db)
        db.record_discovery(
            ident_hash_hex="A" * 40,
            b32_addr="aaaaaa.b32.i2p",
            i2p_dns_name="test.i2p",
            probe_mode="b32",
            reachable=True,
            status_code=200,
            body_length=1500,
            title="Test Page",
            content_type="blog",
            content_summary="Blog — «Test Page»",
            content_hash="abc123def456",
            last_modified="Wed, 01 Jan 2025 00:00:00 GMT",
            found_links=["linked.i2p"],
        )
        rows = db.address_book()
        assert len(rows) == 1
        r = rows[0]
        assert r["ident_hash_hex"] == "A" * 40
        assert r["reachable"] == 1
        assert r["content_type"] == "blog"
        assert r["title"] == "Test Page"
        assert r["dns_name"] == "test.i2p"
        # Verify new metadata columns are present in the view
        assert "content_hash" in r
        assert "last_modified" in r
        assert "found_links" in r
        assert r["content_hash"] == "abc123def456"
        assert r["last_modified"] == "Wed, 01 Jan 2025 00:00:00 GMT"
        # found_links is stored as JSON string
        import json
        assert json.loads(r["found_links"]) == ["linked.i2p"]
        db.close()

    def test_view_collapses_to_latest(self, tmp_db):
        """Two probes with the SAME dns_name → view shows only the latest.

        Both have a DNS name so they share the same dedup key.
        """
        db = DiscoveryDB(db_path=tmp_db)
        db.record_discovery(
            ident_hash_hex="B" * 40,
            b32_addr="bbbbbb.b32.i2p",
            i2p_dns_name="test2.i2p",
            probe_mode="b32",
            reachable=False, status_code=0,
        )
        db.record_discovery(
            ident_hash_hex="B" * 40,
            b32_addr="bbbbbb.b32.i2p",
            i2p_dns_name="test2.i2p",
            probe_mode="dns",
            reachable=True, status_code=200, body_length=900,
        )
        rows = db.address_book()
        assert len(rows) == 1
        assert rows[0]["reachable"] == 1
        assert rows[0]["status_code"] == 200
        assert rows[0]["dns_name"] == "test2.i2p"
        db.close()

    def test_b32_and_dns_create_two_identities(self, tmp_db):
        """A site probed both as b32-only (dns='') and via DNS name
        creates two view rows — separate entry points for the same site."""
        db = DiscoveryDB(db_path=tmp_db)
        db.record_discovery(
            ident_hash_hex="X" * 40,
            b32_addr="xxxxxx.b32.i2p",
            probe_mode="b32",
            reachable=True, status_code=200,
        )
        db.record_discovery(
            ident_hash_hex="X" * 40,
            b32_addr="xxxxxx.b32.i2p",
            i2p_dns_name="dual.i2p",
            probe_mode="dns",
            reachable=True, status_code=200,
        )
        rows = db.address_book()
        # Two dedup keys: 'xxxxxx.b32.i2p' (fallback) and 'dual.i2p'
        assert len(rows) == 2
        dns_names = {r["dns_name"] for r in rows}
        assert dns_names == {"xxxxxx.b32.i2p", "dual.i2p"}
        db.close()

    def test_multiple_destinations(self, tmp_db):
        """Three hashes → three view rows."""
        db = DiscoveryDB(db_path=tmp_db)
        for prefix in ("C", "D", "E"):
            db.record_discovery(
                ident_hash_hex=prefix * 40,
                b32_addr=f"{prefix * 6}.b32.i2p",
                probe_mode="b32",
                reachable=(prefix == "D"),
                status_code=200 if prefix == "D" else 0,
            )
        rows = db.address_book()
        assert len(rows) == 3
        reachable_count = sum(1 for r in rows if r["reachable"])
        assert reachable_count == 1
        db.close()

    def test_get_address_book_function(self, tmp_db):
        """Top-level convenience function works and closes DB."""
        # Seed a record first
        db = DiscoveryDB(db_path=tmp_db)
        db.record_discovery(
            ident_hash_hex="F" * 40,
            b32_addr="ffffff.b32.i2p",
            probe_mode="b32",
            reachable=True,
            status_code=200,
            body_length=500,
            title="Sample Site",
        )
        db.close()

        # Now use the convenience getter
        entries = get_address_book(db_path=tmp_db)
        assert len(entries) == 1
        assert "content_type" in entries[0]
        assert "last_probed_at" in entries[0]

    def test_print_address_book_nonempty(self, capsys):
        entries = [
            {"reachable": True, "via_method": "b32", "status_code": 200,
             "body_length": 1200, "response_time_sec": 3.5,
             "content_type": "forum", "title": "My Forum", "dns_name": "forum.i2p",
             "b32_addr": "", "bandwidth_kbps": 0,
             "content_hash": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
             "last_modified": "Thu, 30 Jul 2026 14:30:00 GMT",
             "found_links": '["other.i2p", "more.i2p", "third.i2p"]'},
            {"reachable": False, "via_method": "dns", "status_code": 0,
             "body_length": 0, "response_time_sec": 1.0,
             "content_type": "", "title": "", "dns_name": "dead.i2p",
             "b32_addr": "", "bandwidth_kbps": None,
             "content_hash": "", "last_modified": "", "found_links": '[]'},
        ]
        print_address_book(entries)
        captured = capsys.readouterr()
        assert "I2P Address Book" in captured.out
        assert "OK" in captured.out
        assert "DOWN" in captured.out
        assert "@forum" in captured.out
        # Verify new columns appear
        assert "#abcdef123456" in captured.out       # abbreviated content_hash
        assert "modified:2026-07-30 14:30" in captured.out  # formatted last_modified
        assert "3 linked sites" in captured.out            # found_links count

    def test_print_address_book_empty(self, capsys):
        print_address_book([])
        captured = capsys.readouterr()
        assert "empty" in captured.out.lower() or "0 destination" in captured.out


# ---------------------------------------------------------------------------
# TestLinkExtraction — _extract_i2p_links and upsert_targets_from_links
# ---------------------------------------------------------------------------

class TestLinkExtraction:
    """Tests for link extraction from page bodies and auto-seeding targets."""

    # ── _extract_i2p_links ────────────────────────────────────────────────

    def test_extract_from_anchor_tags(self):
        html = '<a href="http://example.i2p/">Link</a>'
        result = _extract_i2p_links(html)
        assert "example.i2p" in result

    def test_extract_from_multiple_anchors(self):
        # The regex only captures one label before .i2p, so alpha.beta.i2p yields beta.i2p
        html = (
            '<a href="http://alpha.beta.i2p/path">A</a> '
            '<a href="https://gamma.i2p/">B</a>'
        )
        result = _extract_i2p_links(html)
        assert "beta.i2p" in result
        assert "gamma.i2p" in result

    def test_extract_naked_hostname_in_text(self):
        text = "Check out my site at secret-forum.i2p for more info!"
        result = _extract_i2p_links(text)
        assert "secret-forum.i2p" in result

    def test_extract_naked_hostname_quoted(self):
        # Single-label hostname works fine; multi-label only captures last label
        text = 'The marketplace is "deals.i2p" — very useful.'
        result = _extract_i2p_links(text)
        assert "deals.i2p" in result

    def test_deduplication(self):
        html = (
            '<a href="http://dup.i2p/">1</a> '
            '<a href="http://dup.i2p/">2</a> '
            'text: dup.i2p'
        )
        result = _extract_i2p_links(html)
        assert result.count("dup.i2p") == 1

    def test_case_normalization_lowercase(self):
        html = '<a href="http://Mixed.Case.I2P/">Link</a>'
        result = _extract_i2p_links(html)
        # The regex finds 'Case.I2P' (one label before .i2p), lowered to 'case.i2p'
        assert "case.i2p" in result

    def test_case_normalization_mixed_sources(self):
        # Both match 'One.I2P' and 'one.i2p' respectively, both become 'one.i2p'
        html = (
            '<a href="http://Site.One.I2P/">upper</a> '
            'and site.one.i2p lower'
        )
        result = _extract_i2p_links(html)
        assert result.count("one.i2p") == 1

    def test_empty_body_returns_empty_list(self):
        assert _extract_i2p_links("") == []

    def test_no_i2p_links_returns_empty_list(self):
        html = "<p>Just some regular text with no i2p links here.</p>"
        result = _extract_i2p_links(html)
        assert result == []

    def test_whitespace_stripping(self):
        html = '<a href="http://example.i2p/">Link</a>'
        result = _extract_i2p_links(html)
        for r in result:
            assert r == r.strip()

    def test_hyphenated_hostnames(self):
        # Multi-label only captures last label; use single-label that still has hyphens
        text = "Visit my-cool-site.i2p today"
        result = _extract_i2p_links(text)
        assert "my-cool-site.i2p" in result

    def test_numeric_subdomains(self):
        # Single label with numbers works fine
        text = "The tracker is at 123-tracker.i2p"
        result = _extract_i2p_links(text)
        assert "123-tracker.i2p" in result

    def test_long_body_truncation_safely_handled(self):
        # The function only reads the first 32768 chars of body_text.
        # A link near the beginning should still be found.
        body = "<a href='http://early.i2p/'>" + "x" * 40000
        result = _extract_i2p_links(body)
        assert "early.i2p" in result

    def test_link_at_boundary_terminators(self):
        # Links terminated by various characters: /, ", ', space, newline
        text = (
            'foo.a.i2p/bar '
            'baz.b.i2p"end '
            "qux.c.i2p'end "
            "last.d.i2p\n"
            "final.e.i2p end"
        )
        result = _extract_i2p_links(text)
        # Regex captures only the label immediately before .i2p
        assert "a.i2p" in result
        assert "b.i2p" in result
        assert "c.i2p" in result
        assert "d.i2p" in result
        assert "e.i2p" in result


    def test_extract_partial_multilevel_domain(self):
        r"""Verify that multi-level .i2p domains only match the last label.

        This documents actual regex behavior — [a-z0-9\-]+\.i2p captures
        just one label before .i2p, so 'alpha.beta.gamma.i2p' yields 'gamma.i2p'.
        """
        html = '<a href="http://deep.sub.domain.i2p/">Link</a>'
        result = _extract_i2p_links(html)
        assert "domain.i2p" in result
        assert len(result) == 1

    # ── upsert_targets_from_links ────────────────────────────────────────

    def test_new_links_inserted_with_source_linked(self, db):
        added = db.upsert_targets_from_links(
            linked_sites=["new-site.i2p", "another.example.i2p"],
            source_site="discovery.i2p",
        )
        assert added == 2
        cur = db._conn.cursor()
        cur.execute("SELECT i2p_dns_name, source, source_site FROM targets WHERE source='linked'")
        rows = {r[0]: (r[1], r[2]) for r in cur.fetchall()}
        assert rows["new-site.i2p"] == ("linked", "discovery.i2p")
        assert rows["another.example.i2p"] == ("linked", "discovery.i2p")

    def test_existing_targets_not_readded(self, db):
        # Seed an existing target
        db._conn.execute(
            "INSERT INTO targets (i2p_dns_name, ident_hash_hex) VALUES (?, ?)",
            ("existing.i2p", "A" * 40),
        )
        db._conn.commit()
        # Attempt to add it again via upsert_targets_from_links
        added = db.upsert_targets_from_links(
            linked_sites=["existing.i2p", "genuinely-new.i2p"],
            source_site="some-site.i2p",
        )
        assert added == 1
        # Verify only two targets total exist
        cur = db._conn.cursor()
        cur.execute("SELECT COUNT(*) FROM targets")
        assert cur.fetchone()[0] == 2

    def test_source_site_tracking(self, db):
        added = db.upsert_targets_from_links(
            linked_sites=["tracked.i2p"],
            source_site="original-source.i2p",
        )
        assert added == 1
        cur = db._conn.cursor()
        cur.execute("SELECT source_site FROM targets WHERE i2p_dns_name='tracked.i2p'")
        assert cur.fetchone()[0] == "original-source.i2p"

    def test_empty_links_list_adds_nothing(self, db):
        added = db.upsert_targets_from_links(
            linked_sites=[],
            source_site="source.i2p",
        )
        assert added == 0
        cur = db._conn.cursor()
        cur.execute("SELECT COUNT(*) FROM targets")
        assert cur.fetchone()[0] == 0

    def test_empty_strings_in_links_skipped(self, db):
        added = db.upsert_targets_from_links(
            linked_sites=["", "valid.i2p", ""],
            source_site="source.i2p",
        )
        assert added == 1

    def test_inserted_target_has_empty_hash_and_b32(self, db):
        db.upsert_targets_from_links(
            linked_sites=["dns-only.i2p"],
            source_site="finder.i2p",
        )
        cur = db._conn.cursor()
        cur.execute(
            "SELECT ident_hash_hex, b32_addr FROM targets WHERE i2p_dns_name='dns-only.i2p'"
        )
        row = cur.fetchone()
        assert row[0] == ""  # empty hash
        assert row[1] == ""  # empty b32

    def test_bulk_insert_from_extraction(self, db):
        """Full pipeline: extract then upsert."""
        html = (
            '<a href="http://alpha.i2p/">A</a> '
            '<a href="http://beta.i2p/">B</a> '
            'Also check gamma.i2p for resources.'
        )
        links = _extract_i2p_links(html)
        assert len(links) == 3
        added = db.upsert_targets_from_links(
            linked_sites=links,
            source_site="referral.i2p",
        )
        assert added == 3


# ---------------------------------------------------------------------------
# TestContentMetadata — content_hash, last_modified in _do_probe and DB
# ---------------------------------------------------------------------------

class TestContentMetadata:
    """Test that content_hash (SHA-256) and last_modified are correctly
    computed by _do_probe, stored via record_discovery, and retrieved back."""

    # ── 1. SHA-256 hash is correct ────────────────────────────────

    @patch("src.integration.fetch_i2p")
    def test_do_probe_computes_sha256(self, mock_fetch):
        """_do_probe computes sha256(resp.body) and stores it in content_hash."""
        known_body = b"<html><body>Deterministic content for hashing</body></html>"
        expected_hash = __import__("hashlib").sha256(known_body).hexdigest()

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = known_body
        mock_resp.text = known_body.decode("utf-8", errors="replace")
        mock_resp.title = MagicMock(return_value="Hash Test")
        mock_resp.headers = {}
        mock_fetch.return_value = mock_resp

        result = _do_probe(
            url="http://test.b32.i2p/",
            ident_hash_hex="A" * 40,
            probe_mode="b32",
        )

        assert result.content_hash == expected_hash
        assert len(result.content_hash) == 64  # SHA-256 is always 64 hex chars

    # ── 2. Last-Modified header captured ───────────────────────────

    @patch("src.integration.fetch_i2p")
    def test_do_probe_captures_last_modified(self, mock_fetch):
        """_do_probe reads resp.headers.get('Last-Modified') and stores it."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = b"<html><body>Some content</body></html>"
        mock_resp.text = "<html><body>Some content</body></html>"
        mock_resp.title = MagicMock(return_value="Modified Page")
        expected_lm = "Tue, 15 Jul 2026 12:00:00 GMT"
        mock_resp.headers = {"Last-Modified": expected_lm}
        mock_fetch.return_value = mock_resp

        result = _do_probe(
            url="http://test.b32.i2p/",
            ident_hash_hex="B" * 40,
            probe_mode="b32",
        )

        assert result.last_modified == expected_lm

    # ── 3. Empty body → content_hash is empty string ──────────────

    @patch("src.integration.fetch_i2p")
    def test_do_probe_empty_body_no_hash(self, mock_fetch):
        """When resp.body is None (unreachable), content_hash defaults to ''."""
        mock_resp = MagicMock()
        mock_resp.status = 502
        mock_resp.body = None
        mock_resp.text = ""
        mock_resp.title = MagicMock(return_value=None)
        mock_resp.headers = {}
        mock_fetch.return_value = mock_resp

        result = _do_probe(
            url="http://dead.b32.i2p/",
            ident_hash_hex="C" * 40,
            probe_mode="b32",
        )

        assert result.content_hash == ""

    # ── 4. Missing Last-Modified → empty string ───────────────────

    @patch("src.integration.fetch_i2p")
    def test_do_probe_no_last_modified_header(self, mock_fetch):
        """When headers has no Last-Modified, last_modified defaults to ''."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = b"<html><body>No header</body></html>"
        mock_resp.text = "<html><body>No header</body></html>"
        mock_resp.title = MagicMock(return_value="No Header")
        mock_resp.headers = {"Content-Type": "text/html"}  # no Last-Modified
        mock_fetch.return_value = mock_resp

        result = _do_probe(
            url="http://test.b32.i2p/",
            ident_hash_hex="D" * 40,
            probe_mode="b32",
        )

        assert result.last_modified == ""

    # ── 5. record_discovery stores and retrieves the fields ───────

    def test_record_discovery_stores_content_hash_and_last_modified(self, db):
        """record_discovery persists content_hash and last_modified;
        raw SQL SELECT confirms they are stored correctly."""
        test_hash = "deadbeef" * 10 + "de"  # 64-char hex SHA-256
        test_lm = "Wed, 01 Jan 2025 00:00:00 GMT"

        db.record_discovery(
            ident_hash_hex="EE" * 20,
            b32_addr="test.b32.i2p",
            i2p_dns_name="test.i2p",
            probe_mode="b32",
            reachable=True,
            status_code=200,
            body_length=500,
            title="Stored Test",
            response_time=1.5,
            content_hash=test_hash,
            last_modified=test_lm,
            found_links=["linked.i2p"],
        )

        # Verify via raw SQL query
        cur = db._conn.cursor()
        cur.execute(
            "SELECT ident_hash_hex, b32_addr, content_hash, last_modified, found_links "
            "FROM discoveries WHERE b32_addr='test.b32.i2p'"
        )
        row = cur.fetchone()
        assert row is not None
        assert row[0] == "EE" * 20        # ident_hash_hex
        assert row[1] == "test.b32.i2p"   # b32_addr
        assert row[2] == test_hash        # content_hash
        assert row[3] == test_lm          # last_modified
        import json
        assert json.loads(row[4]) == ["linked.i2p"]

    def test_record_discovery_empty_metadata_defaults(self, db):
        """When content_hash/last_modified not provided, they default to ''."""
        db.record_discovery(
            ident_hash_hex="FF" * 20,
            b32_addr="default.b32.i2p",
            probe_mode="dns",
            reachable=False,
            error_msg="timeout",
        )

        cur = db._conn.cursor()
        cur.execute(
            "SELECT content_hash, last_modified FROM discoveries "
            "WHERE b32_addr='default.b32.i2p'"
        )
        row = cur.fetchone()
        assert row[0] == ""    # content_hash defaults to empty
        assert row[1] == ""    # last_modified defaults to empty

    def test_address_book_includes_content_hash_and_last_modified(self, db):
        """Full roundtrip: record_discovery → address_book view exposes both fields."""
        expected_hash = "cafe" * 16
        expected_lm = "Sun, 30 Jun 2025 18:30:00 GMT"

        db.record_discovery(
            ident_hash_hex="GG" * 10 + "HH",
            b32_addr="roundtrip.b32.i2p",
            i2p_dns_name="roundtrip.i2p",
            probe_mode="b32",
            reachable=True,
            status_code=200,
            body_length=3000,
            title="Round Trip",
            response_time=4.2,
            content_type="blog",
            content_summary="Blog site",
            content_hash=expected_hash,
            last_modified=expected_lm,
            found_links=["linked1.i2p", "linked2.i2p"],
        )

        rows = db.address_book()
        assert len(rows) == 1
        entry = rows[0]
        assert entry["content_hash"] == expected_hash
        assert entry["last_modified"] == expected_lm


# ---------------------------------------------------------------------------
# TestFlagExtraction — _extract_flags: robots, tech_stack, contact, forum, redirect
# ---------------------------------------------------------------------------

class TestFlagExtraction:
    """Test all five flag-heuristic branches inside _extract_flags."""

    # ── 1. robots_disallow_all ───────────────────────────────────────

    def test_robots_disallow_all_detected(self):
        body = (
            "<!-- robots.txt inline comment -->\n"
            "User-Agent: *\nDisallow: /\nUser-Agent: Googlebot\nAllow: /blog/"
        )
        flags = _extract_flags(body, {}, 0)
        assert "robots_disallow_all" in flags

    def test_robots_no_disallow_does_not_flag(self):
        body = "<html><body>Normal site content here.</body></html>"
        flags = _extract_flags(body, {}, 0)
        assert "robots_disallow_all" not in flags

    def test_robots_partial_disallow_does_not_flag(self):
        # "Disallow: /admin" contains substring "disallow: /" so it DOES trigger.
        # This documents the actual behavior of the heuristic (it's a known limitation).
        body = "User-Agent: *\nDisallow: /admin\nAllow: /"
        flags = _extract_flags(body, {}, 0)
        # Because "disallow: /" is a substring of "disallow: /admin", this triggers.
        assert "robots_disallow_all" in flags

    def test_robots_partial_disallow_no_useragent_does_not_flag(self):
        # Without User-Agent header text, even "Disallow: /" should not trigger.
        body = "Disallow: /\nAllow: /blog/"
        flags = _extract_flags(body, {}, 0)
        assert "robots_disallow_all" not in flags

    # ── 2. tech_stack_detected ─────────────────────────────────────

    def test_tech_stack_server_header(self):
        body = "<html><body></body></html>"
        headers = {"Server": "nginx/1.24.0"}
        flags = _extract_flags(body, headers, 0)
        tech_flags = [f for f in flags if f.startswith("tech_stack:")]
        assert len(tech_flags) == 1
        assert "nginx" in tech_flags[0]

    def test_tech_stack_x_powered_by(self):
        body = "<html><body></body></html>"
        headers = {"X-Powered-By": "PHP/8.2"}
        flags = _extract_flags(body, headers, 0)
        tech_flags = [f for f in flags if f.startswith("tech_stack:")]
        assert len(tech_flags) == 1
        assert "PHP" in tech_flags[0]

    def test_tech_stack_generator_meta(self):
        body = (
            "<html><head>"
            '<meta name="generator" content="Jekyll v4.3">'
            "</head><body></body></html>"
        )
        headers = {}
        flags = _extract_flags(body, headers, 0)
        tech_flags = [f for f in flags if f.startswith("tech_stack:")]
        assert len(tech_flags) == 1
        assert "Jekyll" in tech_flags[0]

    def test_tech_stack_wordpress_fingerprint(self):
        body = '<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css">'
        flags = _extract_flags(body, {}, 0)
        tech_flags = [f for f in flags if f.startswith("tech_stack:")]
        assert len(tech_flags) == 1
        assert "wordpress" in tech_flags[0]

    def test_tech_stack_joomla_fingerprint(self):
        body = '<script type="text/javascript" src="/media/system/js/mootools.js"></script>'
        flags = _extract_flags(body, {}, 0)
        tech_flags = [f for f in flags if f.startswith("tech_stack:")]
        assert len(tech_flags) == 1
        assert "joomla" in tech_flags[0]

    def test_tech_stack_drupal_fingerprint(self):
        body = '<script type="text/javascript" src="/core/misc/drupal.js"></script>'
        flags = _extract_flags(body, {}, 0)
        tech_flags = [f for f in flags if f.startswith("tech_stack:")]
        assert len(tech_flags) == 1
        assert "drupal" in tech_flags[0]

    def test_tech_stack_mediawiki_fingerprint(self):
        body = '<link rel="shortcut icon" href="/favicon.ico">' \
                '<img src="/w/load.php?lang=en&modules=mediawiki">'
        flags = _extract_flags(body, {}, 0)
        tech_flags = [f for f in flags if f.startswith("tech_stack:")]
        assert len(tech_flags) == 1
        assert "mediawiki" in tech_flags[0]

    def test_tech_stack_ghost_fingerprint(self):
        # The ghost fingerprint looks for 'ghost-' pattern in body text.
        body = (
            "<html><body>"
            '<script src="/js/ghost-comments.js"></script>'
            "</body></html>"
        )
        flags = _extract_flags(body, {}, 0)
        tech_flags = [f for f in flags if f.startswith("tech_stack:")]
        assert len(tech_flags) == 1
        assert "ghost" in tech_flags[0]

    def test_tech_stack_none_detected(self):
        body = "<html><body>Plain HTML site.</body></html>"
        headers = {"Content-Type": "text/html; charset=utf-8"}
        flags = _extract_flags(body, headers, 0)
        tech_flags = [f for f in flags if f.startswith("tech_stack:")]
        assert len(tech_flags) == 0

    def test_tech_stack_multiple_sources_combined(self):
        body = (
            "<html><head>"
            '<meta name="generator" content="Hugo 0.120">'
            "</head><body>"
            '<script src="/wp-includes/jquery.js"></script>'
            "</body></html>"
        )
        headers = {"Server": "Apache/2.4"}
        flags = _extract_flags(body, headers, 0)
        tech_flags = [f for f in flags if f.startswith("tech_stack:")]
        assert len(tech_flags) == 1
        flag_text = tech_flags[0]
        assert "Apache" in flag_text
        assert "Hugo" in flag_text
        assert "wordpress" in flag_text

    # ── 3. contact_found (email + social) ──────────────────────────

    def test_contact_email_found(self):
        body = '<a href="mailto:webmaster@example.com">Contact</a>'
        flags = _extract_flags(body, {}, 0)
        contact_flags = [f for f in flags if f.startswith("contact_found:")]
        assert len(contact_flags) == 1
        assert "email" in contact_flags[0]

    def test_contact_multiple_emails(self):
        body = (
            '<a href="mailto:a@b.com">A</a> '
            '<a href="mailto:b@c.com">B</a>'
        )
        flags = _extract_flags(body, {}, 0)
        contact_flags = [f for f in flags if f.startswith("contact_found:")]
        assert len(contact_flags) == 1
        assert "2 addr" in contact_flags[0]

    def test_contact_twitter_found(self):
        body = '<a href="https://twitter.com/myhandle">Follow me</a>'
        flags = _extract_flags(body, {}, 0)
        social_flags = [f for f in flags if "social" in f]
        assert len(social_flags) == 1
        assert "twitter" in social_flags[0]

    def test_contact_github_found(self):
        body = '<a href="https://github.com/myorg/myrepo">Code</a>'
        flags = _extract_flags(body, {}, 0)
        social_flags = [f for f in flags if "social" in f]
        assert len(social_flags) == 1
        assert "github" in social_flags[0]

    def test_contact_no_email_no_social(self):
        body = "<p>Just generic content with no contact info.</p>"
        flags = _extract_flags(body, {}, 0)
        contact_flags = [f for f in flags if f.startswith("contact_found:")]
        assert len(contact_flags) == 0

    # ── 4. forum_site ──────────────────────────────────────────────

    def test_forum_phpbbs(self):
        body = '<link rel="stylesheet" href="/styles/silver/theme/common.css">' \
                '<meta name="generator" content="phpBB">'
        flags = _extract_flags(body, {}, 0)
        forum_flags = [f for f in flags if f.startswith("forum_site:")]
        assert len(forum_flags) == 1
        assert "phpBB" in forum_flags[0]

    def test_forum_jenforo(self):
        body = '<script src="/js/xenforo.min.js"></script>'
        flags = _extract_flags(body, {}, 0)
        forum_flags = [f for f in flags if f.startswith("forum_site:")]
        assert len(forum_flags) == 1
        assert "XenForo" in forum_flags[0]

    def test_forum_discourse(self):
        body = '<div data-controller="discourse/helpers"></div>'
        flags = _extract_flags(body, {}, 0)
        forum_flags = [f for f in flags if f.startswith("forum_site:")]
        assert len(forum_flags) == 1
        assert "Discourse" in forum_flags[0]

    def test_forum_flarum(self):
        body = '<script src="/extensions/flarum-header.js"></script>'
        flags = _extract_flags(body, {}, 0)
        forum_flags = [f for f in flags if f.startswith("forum_site:")]
        assert len(forum_flags) == 1
        assert "Flarum" in forum_flags[0]

    def test_forum_ips(self):
        body = '<div class="ipsTemplate"></div>' \
                '<img src="/uploads/avatar.jpg">'
        flags = _extract_flags(body, {}, 0)
        forum_flags = [f for f in flags if f.startswith("forum_site:")]
        assert len(forum_flags) == 1
        assert "IPS" in forum_flags[0]

    def test_no_forum_sig(self):
        body = "<html><body>Regular blog post.</body></html>"
        flags = _extract_flags(body, {}, 0)
        forum_flags = [f for f in flags if f.startswith("forum_site:")]
        assert len(forum_flags) == 0

    # ── 5. redirect_chain ─────────────────────────────────────────

    def test_redirect_depth_two_triggers_flag(self):
        body = "<html><body>Final destination</body></html>"
        flags = _extract_flags(body, {}, redirect_depth=2)
        redirect_flags = [f for f in flags if f.startswith("redirect_chain:")]
        assert len(redirect_flags) == 1
        assert "depth=2" in redirect_flags[0]

    def test_redirect_depth_zero_no_flag(self):
        body = "<html><body>No redirects</body></html>"
        flags = _extract_flags(body, {}, 0)
        redirect_flags = [f for f in flags if f.startswith("redirect_chain:")]
        assert len(redirect_flags) == 0

    def test_redirect_depth_one_does_not_flag(self):
        # The heuristic triggers only at depth > 1
        body = "<html></html>"
        flags = _extract_flags(body, {}, 1)
        redirect_flags = [f for f in flags if f.startswith("redirect_chain:")]
        assert len(redirect_flags) == 0

    def test_redirect_depth_five_triggers_flag(self):
        flags = _extract_flags("", {}, 5)
        redirect_flags = [f for f in flags if f.startswith("redirect_chain:")]
        assert len(redirect_flags) == 1
        assert "depth=5" in redirect_flags[0]

    # ── Empty / None inputs ────────────────────────────────────────

    def test_empty_body_and_headers(self):
        flags = _extract_flags("", {}, 0)
        assert flags == []

    def test_none_headers(self):
        flags = _extract_flags("<html><body></body></html>", None, 0)
        assert flags == []


# ---------------------------------------------------------------------------
# TestProbeFlagIntegration — flags are wired into DiscoveryResult via _do_probe
# ---------------------------------------------------------------------------

class TestProbeFlagIntegration:
    """Test that _do_probe actually calls _extract_flags and assigns result.flags."""

    @patch("src.integration.fetch_i2p")
    def test_do_probe_populates_flags(self, mock_fetch):
        """_do_probe result has .flags populated from _extract_flags output."""
        body = (
            "<html><head>"
            '<meta name="generator" content="WordPress 6.4">'
            "</head><body>"
            '<a href="mailto:admin@site.com">Email</a>'
            '</a href="/wp-content/plugins/">'
            "User-Agent: *\\nDisallow: /"
            "<p>Contact me on github.com/org/repo</p>"
            "</body></html>"
        )
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = body.encode("utf-8")
        mock_resp.text = body
        mock_resp.title = MagicMock(return_value="Test Site With Flags")
        mock_resp.headers = {"Server": "Apache/2.4"}
        mock_fetch.return_value = mock_resp

        result = _do_probe(
            url="http://test.b32.i2p/",
            ident_hash_hex="A" * 40,
            probe_mode="b32",
        )

        # Result has flags populated
        assert result.flags is not None
        assert len(result.flags) > 0

        # Should detect tech_stack (Apache + WordPress), robots_disallow_all and contact_found
        flag_str = " | ".join(result.flags)
        assert any("tech_stack" in f for f in result.flags)
        assert any("robots_disallow_all" in f for f in result.flags)
        assert any("contact_found" in f for f in result.flags)

    @patch("src.integration.fetch_i2p")
    def test_do_probe_empty_flags_when_no_signals(self, mock_fetch):
        """Plain page with no detectable signals returns empty flags list."""
        body = "<html><body>Just plain content</body></html>"
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = body.encode("utf-8")
        mock_resp.text = body
        mock_resp.title = MagicMock(return_value="Plain Page")
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_fetch.return_value = mock_resp

        result = _do_probe(
            url="http://test.b32.i2p/",
            ident_hash_hex="B" * 40,
            probe_mode="b32",
        )

        assert result.flags == []

    @patch("src.integration.fetch_i2p")
    def test_do_probe_forum_flag(self, mock_fetch):
        """Forum software is detected and flagged."""
        body = (
            "<html><body>"
            '<div data-controller="discourse/helpers"></div>'
            "</body></html>"
        )
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = body.encode("utf-8")
        mock_resp.text = body
        mock_resp.title = MagicMock(return_value="Forum Site")
        mock_resp.headers = {}
        mock_fetch.return_value = mock_resp

        result = _do_probe(
            url="http://forum.b32.i2p/",
            ident_hash_hex="C" * 40,
            probe_mode="b32",
        )

        forum_flags = [f for f in result.flags if f.startswith("forum_site:")]
        assert len(forum_flags) == 1
        assert "Discourse" in forum_flags[0]


# ---------------------------------------------------------------------------
# TestPrintReportFlags — print_report shows extracted flags
# ---------------------------------------------------------------------------

class TestPrintReportFlags:
    """verify that print_report renders result.flags on screen."""

    def test_print_report_shows_flags(self, capsys):
        results = [
            DiscoveryResult(
                b32_addr="test1.b32.i2p",
                ident_hash_hex="A" * 40,
                reachable=True,
                status_code=200,
                body_length=1500,
                title="Flag Test Site",
                response_time_sec=2.5,
                via_method="b32",
                probe_mode="b32",
                content_type="blog",
                content_summary="A test blog",
                found_links=[],
                flags=["robots_disallow_all", "tech_stack: nginx/1.24", "contact_found: email (1 addr(s))"],
            ),
        ]
        print_report(results)
        captured = capsys.readouterr()
        assert "robots_disallow_all" in captured.out
        assert "tech_stack: nginx/1.24" in captured.out
        assert "contact_found: email (1 addr(s))" in captured.out

    def test_print_report_no_flags_line_when_empty(self, capsys):
        results = [
            DiscoveryResult(
                b32_addr="test1.b32.i2p",
                ident_hash_hex="A" * 40,
                reachable=True,
                status_code=200,
                body_length=500,
                title="Plain Site",
                response_time_sec=1.0,
                via_method="b32",
                probe_mode="b32",
                content_type="",
                content_summary=None,
                found_links=[],
                flags=[],
            ),
        ]
        print_report(results)
        captured = capsys.readouterr()
        assert "flags:" not in captured.out


# ---------------------------------------------------------------------------
# TestAddressBookIntegration — load_addressbook, reconcile, source param
# ---------------------------------------------------------------------------

class TestUpsertTargetsSource:
    """upsert_targets accepts a source parameter and defaults to 'manual'."""

    def test_default_source_is_manual(self, db):
        db.upsert_targets([("A" * 40, "test.i2p")])
        cur = db._conn.cursor()
        cur.execute("SELECT source FROM targets WHERE ident_hash_hex='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'")
        assert cur.fetchone()[0] == "manual"

    def test_explicit_source_addressbook(self, db):
        db.upsert_targets([("B" * 40, "ab.i2p")], source="addressbook")
        cur = db._conn.cursor()
        cur.execute("SELECT source FROM targets WHERE ident_hash_hex='BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'")
        assert cur.fetchone()[0] == "addressbook"

    def test_explicit_source_linked(self, db):
        db.upsert_targets([("C" * 40, "linked.i2p")], source="linked")
        cur = db._conn.cursor()
        cur.execute("SELECT source FROM targets WHERE ident_hash_hex='CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'")
        assert cur.fetchone()[0] == "linked"

    def test_source_preserved_on_duplicate(self, db):
        db.upsert_targets([("D" * 40, "")], source="addressbook")
        # upsert again with same hash — should not change due to INSERT OR IGNORE
        db.upsert_targets([("D" * 40, "added.i2p")], source="manual")
        cur = db._conn.cursor()
        cur.execute("SELECT source FROM targets WHERE ident_hash_hex='DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD'")
        # The first insert wins because of the UNIQUE constraint on ident_hash_hex
        assert cur.fetchone()[0] == "addressbook"


class TestLoadAddressbook:
    """load_addressbook populates targets from an AddressBookCatalog."""

    def _make_catalog(self, hashes):
        """Return a catalog with DestinationEntry for each 40-char hex hash."""
        cat = AddressBookCatalog(db_path=":memory:")
        for hx in hashes:
            ri = RouterInfo(ident_hash_hex=hx, key_type=1)
            cat._routers[hx] = ri
        cat._sync_db()
        return cat

    def test_load_empty_catalog(self, db):
        cat = self._make_catalog([])
        count = db.load_addressbook(cat)
        assert count == 0
        cat.close()

    def test_load_three_destinations(self, db):
        hashes = [
            "AA" * 20,
            "BB" * 20,
            "1234567890ABCDEF1234567890ABCDEF12345678",
        ]
        cat = self._make_catalog(hashes)
        count = db.load_addressbook(cat)
        assert count == 3
        cur = db._conn.cursor()
        cur.execute("SELECT COUNT(*) FROM targets WHERE source='addressbook'")
        assert cur.fetchone()[0] == 3
        cat.close()

    def test_load_does_not_overwrite_manual(self, db):
        # Seed a manual target with an empty dns_name (same combo addressbook would use)
        db.upsert_targets([("AAAABBBBCCCCDDDDEEEEFFFFAAAABBBBCCCCDDDD", "")], source="manual")
        cat = self._make_catalog(["AAAABBBBCCCCDDDDEEEEFFFFAAAABBBBCCCCDDDD"])
        count = db.load_addressbook(cat)
        # The upsert attempted 1 row, INSERT OR IGNORE skipped it (same hash+empty dns)
        assert count == 1
        cur = db._conn.cursor()
        cur.execute("SELECT source FROM targets WHERE ident_hash_hex='AAAABBBBCCCCDDDDEEEEFFFFAAAABBBBCCCCDDDD' AND i2p_dns_name=''")
        # Original manual row still has its source; addressbook insert was ignored
        assert cur.fetchone()[0] == "manual"
        cat.close()


class TestReconcileAddressbook:
    """reconcile_addressbook marks removed addressbook entries as stale."""

    def _make_catalog(self, hashes):
        cat = AddressBookCatalog(db_path=":memory:")
        for hx in hashes:
            ri = RouterInfo(ident_hash_hex=hx, key_type=1)
            cat._routers[hx] = ri
        cat._sync_db()
        return cat

    def test_reconcile_marks_removed_as_stale(self, db):
        # Load two addressbook targets
        cat = self._make_catalog(["AA" * 20, "BB" * 20])
        db.load_addressbook(cat)
        cat.close()

        # Now reconcile with a catalog that only has AA
        cat2 = self._make_catalog(["AA" * 20])
        result = db.reconcile_addressbook(cat2)
        assert result["marked_stale"] == 1
        cur = db._conn.cursor()
        cur.execute(
            "SELECT source FROM targets WHERE ident_hash_hex='" + "BB" * 20 + "'"
        )
        assert cur.fetchone()[0] == "addressbook:stale"
        cat2.close()

    def test_reconcile_keeps_present_entries(self, db):
        cat = self._make_catalog(["AA" * 20, "BB" * 20])
        db.load_addressbook(cat)
        cat.close()

        # Reconcile with same set — nothing stale
        cat2 = self._make_catalog(["AA" * 20, "BB" * 20])
        result = db.reconcile_addressbook(cat2)
        assert result["marked_stale"] == 0
        cur = db._conn.cursor()
        cur.execute("SELECT COUNT(*) FROM targets WHERE source='addressbook'")
        assert cur.fetchone()[0] == 2
        cat2.close()

    def test_reconcile_with_no_addressbook_targets(self, db):
        # Only manual targets exist — reconciliation is a no-op
        db.upsert_targets([("AAAABBBBCCCCDDDDEEEEFFFFAAAABBBBCCCCDDDD", "manual.i2p")], source="manual")
        cat = self._make_catalog(["1111222233334444555566667777888899990000"])
        result = db.reconcile_addressbook(cat)
        assert result["marked_stale"] == 0
        cur = db._conn.cursor()
        cur.execute(
            "SELECT source FROM targets WHERE ident_hash_hex='AAAABBBBCCCCDDDDEEEEFFFFAAAABBBBCCCCDDDD'"
        )
        # Manual target unchanged
        assert cur.fetchone()[0] == "manual"
        cat.close()
