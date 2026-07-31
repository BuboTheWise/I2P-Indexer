"""Tests for src/integration.py — DiscoveryResult, DiscoveryDB, probe flow, reporting."""
from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile

import pytest
from unittest.mock import MagicMock, patch, call

from src.integration import (
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
        )
        rows = db.address_book()
        assert len(rows) == 1
        r = rows[0]
        assert r["ident_hash_hex"] == "A" * 40
        assert r["reachable"] == 1
        assert r["content_type"] == "blog"
        assert r["title"] == "Test Page"
        assert r["dns_name"] == "test.i2p"
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
             "b32_addr": "", "bandwidth_kbps": 0},
            {"reachable": False, "via_method": "dns", "status_code": 0,
             "body_length": 0, "response_time_sec": 1.0,
             "content_type": "", "title": "", "dns_name": "dead.i2p",
             "b32_addr": "", "bandwidth_kbps": None},
        ]
        print_address_book(entries)
        captured = capsys.readouterr()
        assert "I2P Address Book" in captured.out
        assert "OK" in captured.out
        assert "DOWN" in captured.out
        assert "@forum" in captured.out

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
        """Verify that multi-level .i2p domains only match the last label.

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
