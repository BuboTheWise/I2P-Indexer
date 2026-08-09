"""Tests for auto-crawl source_site tracking — verify that targets discovered
via auto-crawl have their source_site column set correctly (the dns_name of
the destination they were found on).

Test strategy:
- Mock fetch_i2p to return HTML containing known .i2p links
- Call probe_destination() which extracts those links and auto-seeds them
- Verify each discovered target has source_site = parent's i2p_dns_name
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from src.integration import (
    DiscoveryDB,
    probe_destination,
)


@pytest.fixture
def tmp_db(tmp_path):
    """A temporary on-disk SQLite database."""
    db_file = str(tmp_path / "test_source_site.db")
    return db_file


@pytest.fixture
def db(tmp_db):
    inst = DiscoveryDB(db_path=tmp_db)
    yield inst
    inst.close()


def _make_mock_response(
    found_links: list[str],
    status: int = 200,
    title_text: str = "Parent Page",
    body_len: int = 512,
):
    """Build a mock urllib response with HTML containing the given .i2p links.

    Each link is embedded as an <a href> in the body text so that
    _extract_i2p_links (via run_extractors) will find them.

    NOTE: The I2P DNS regex only matches [a-z0-9] and hyphens, NOT underscores.
    Domain labels must use hyphens for readability.
    """
    link_tags = " ".join(
        f'<a href="http://{link}/">{link}</a>' for link in found_links
    )
    html_body = (
        f"<html><title>{title_text}</title>\n"
        f"{link_tags}\n"
        + "x" * max(0, body_len - 200)
    ).encode("utf-8")

    mock = MagicMock()
    mock.status = status
    mock.body = html_body
    mock.text = html_body.decode("utf-8", errors="replace")
    mock.title = MagicMock(return_value=title_text)
    mock.headers = {}
    return mock


class TestSourceSiteTracking:
    """Verify that auto-discovered .i2p targets record source_site correctly."""

    @patch("src.integration.fetch_i2p")
    def test_discovered_links_get_source_site_set_to_parent_dns(
        self, mock_fetch, db
    ):
        """When probing parent.i2p and discovering child1/child2 links,
         the discovered targets must have source_site='parent.i2p'."""

        known_links = ["child1.example.i2p", "child2.example.i2p"]
        mock_fetch.return_value = _make_mock_response(known_links)

        ident_hash_hex = "aa" * 20
        probe_destination(
            ident_hash_hex=ident_hash_hex,
            i2p_dns_name="parent.i2p",
            db=db,
            timeout=5.0,
        )

        cur = db._conn.cursor()
        for link in known_links:
            cur.execute(
                "SELECT source_site, source FROM targets WHERE i2p_dns_name = ?",
                (link,),
            )
            row = cur.fetchone()
            assert row is not None, f"Discovered target {link} was not inserted"
            assert row[0] == "parent.i2p", (
                f"Expected source_site='parent.i2p' for {link}, got '{row[0]}'"
            )
            assert row[1] == "linked", (
                f"Expected source='linked' for {link}, got '{row[1]}'"
            )

    @patch("src.integration.fetch_i2p")
    def test_source_site_falls_back_to_hash_prefix_when_no_dns(
        self, mock_fetch, db
    ):
        """When probed by hash only (no i2p_dns_name), source_site should
        fall back to the first 16 chars of ident_hash_hex."""
        known_links = ["fallback-discovered.i2p"]
        mock_fetch.return_value = _make_mock_response(known_links)

        ident_hash_hex = "ab" * 20  # abbabb... (40 hex chars)
        probe_destination(
            ident_hash_hex=ident_hash_hex,
            i2p_dns_name="",
            db=db,
            timeout=5.0,
        )

        cur = db._conn.cursor()
        cur.execute(
            "SELECT source_site FROM targets WHERE i2p_dns_name = ?",
            ("fallback-discovered.i2p",),
        )
        row = cur.fetchone()
        assert row is not None, "Target was not inserted"
        expected_prefix = ident_hash_hex[:16]
        assert row[0] == expected_prefix, (
            f"Expected source_site='{expected_prefix}' (hash prefix), got '{row[0]}'"
        )

    @patch("src.integration.fetch_i2p")
    def test_self_link_excluded_from_auto_seeding(self, mock_fetch, db):
        """The parent site's own DNS name should not be re-seeded as a new target."""
        known_links = ["parent.i2p", "child.i2p"]
        mock_fetch.return_value = _make_mock_response(known_links)

        ident_hash_hex = "aa" * 20
        probe_destination(
            ident_hash_hex=ident_hash_hex,
            i2p_dns_name="parent.i2p",
            db=db,
            timeout=5.0,
        )

        cur = db._conn.cursor()
        # parent.i2p should NOT appear as a linked target
        cur.execute(
            "SELECT COUNT(*) FROM targets WHERE i2p_dns_name = ? AND source = 'linked'",
            ("parent.i2p",),
        )
        assert cur.fetchone()[0] == 0, (
            "Parent site should NOT be inserted as a linked target"
        )

        # child.i2p should exist with correct source_site
        cur.execute(
            "SELECT source_site FROM targets WHERE i2p_dns_name = ?",
            ("child.i2p",),
        )
        row = cur.fetchone()
        assert row is not None
        assert row[0] == "parent.i2p"

    @patch("src.integration.fetch_i2p")
    def test_multiple_discovery_sources_preserve_correct_source_site(
        self, mock_fetch, db
    ):
        """If siteA discovers target-x and siteC discovers target-y, each
        records its own discoverer as source_site."""

        # First probe: "siteA.i2p" discovers "target-x.example.i2p"
        mock_fetch.return_value = _make_mock_response(["target-x.example.i2p"])
        ident_hash_hex_a = "aa" * 20
        probe_destination(
            ident_hash_hex=ident_hash_hex_a,
            i2p_dns_name="siteA.i2p",
            db=db,
            timeout=5.0,
        )

        # Second probe: "siteC.i2p" discovers "target-y.example.i2p"
        mock_fetch.return_value = _make_mock_response(["target-y.example.i2p"])
        ident_hash_hex_c = "cc" * 20
        probe_destination(
            ident_hash_hex=ident_hash_hex_c,
            i2p_dns_name="siteC.i2p",
            db=db,
            timeout=5.0,
        )

        cur = db._conn.cursor()

        # target-x should trace back to siteA
        cur.execute(
            "SELECT source_site FROM targets WHERE i2p_dns_name = ?",
            ("target-x.example.i2p",),
        )
        row_a = cur.fetchone()
        assert row_a is not None, "Target-x should exist in targets"
        assert row_a[0] == "siteA.i2p"

        # target-y should trace back to siteC (not siteA)
        cur.execute(
            "SELECT source_site FROM targets WHERE i2p_dns_name = ?",
            ("target-y.example.i2p",),
        )
        row_c = cur.fetchone()
        assert row_c is not None, "Target-y should exist in targets"
        assert row_c[0] == "siteC.i2p"

    @patch("src.integration.fetch_i2p")
    def test_unreachable_response_still_seeds_links(self, mock_fetch, db):
        """Auto-seeding runs regardless of reachable flag (line 1881 checks
        only best.found_links, not best.reachable). A 503 response that still
        returns HTML with .i2p links will seed those targets — this is by design
        so useful links found on error pages aren't lost."""
        known_links = ["found-on-error-page.i2p"]
        mock_fetch.return_value = _make_mock_response(known_links, status=503)

        ident_hash_hex = "aa" * 20
        probe_destination(
            ident_hash_hex=ident_hash_hex,
            i2p_dns_name="parent.i2p",
            db=db,
            timeout=5.0,
        )

        # Even though reachable=False for status=503, links ARE still seeded
        cur = db._conn.cursor()
        cur.execute(
            "SELECT source_site FROM targets WHERE i2p_dns_name = ?",
            ("found-on-error-page.i2p",),
        )
        row = cur.fetchone()
        assert row is not None, (
            "Auto-seeding runs regardless of reachability — links on error pages still harvested"
        )
        assert row[0] == "parent.i2p"

    @patch("src.integration.fetch_i2p")
    def test_empty_found_links_skips_seeding(self, mock_fetch, db):
        """When found_links is empty (no .i2p links extracted), no targets are seeded."""
        # Mock response with NO .i2p links in the body
        mock_fetch.return_value = _make_mock_response([], status=200)

        ident_hash_hex = "aa" * 20
        probe_destination(
            ident_hash_hex=ident_hash_hex,
            i2p_dns_name="parent.i2p",
            db=db,
            timeout=5.0,
        )

        cur = db._conn.cursor()
        # Only the probed parent should exist (not as linked source)
        cur.execute("SELECT COUNT(*) FROM targets WHERE source = 'linked'")
        assert cur.fetchone()[0] == 0, "No links found means no targets seeded"
        """Client-error status codes (4xx) count as reachable in probe_destination
        (server responded), so found_links ARE auto-seeded — and source_site is set."""
        known_links = ["found-on-404-page.i2p"]
        mock_fetch.return_value = _make_mock_response(known_links, status=404)

        ident_hash_hex = "aa" * 20
        probe_destination(
            ident_hash_hex=ident_hash_hex,
            i2p_dns_name="parent.i2p",
            db=db,
            timeout=5.0,
        )

        cur = db._conn.cursor()
        cur.execute(
            "SELECT source_site FROM targets WHERE i2p_dns_name = ?",
            ("found-on-404-page.i2p",),
        )
        row = cur.fetchone()
        assert row is not None, "4xx responses still count as reachable and seed links"
        assert row[0] == "parent.i2p"

    @patch("src.integration.fetch_i2p")
    def test_existing_target_not_overwritten_with_different_source_site(
        self, mock_fetch, db
    ):
        """If a target was already inserted by one parent, re-discovery by
        another site should NOT overwrite its source_site."""

        # First: "siteA.i2p" discovers "shared-target.i2p"
        mock_fetch.return_value = _make_mock_response(["shared-target.i2p"])
        ident_hash_hex_a = "aa" * 20
        probe_destination(
            ident_hash_hex=ident_hash_hex_a,
            i2p_dns_name="siteA.i2p",
            db=db,
            timeout=5.0,
        )

        cur = db._conn.cursor()
        cur.execute(
            "SELECT source_site FROM targets WHERE i2p_dns_name = ?",
            ("shared-target.i2p",),
        )
        assert cur.fetchone()[0] == "siteA.i2p"

        # Second: "siteB.i2p" also discovers "shared-target.i2p"
        mock_fetch.return_value = _make_mock_response(["shared-target.i2p"])
        ident_hash_hex_b = "bb" * 20
        probe_destination(
            ident_hash_hex=ident_hash_hex_b,
            i2p_dns_name="siteB.i2p",
            db=db,
            timeout=5.0,
        )

        # source_site should still be the first discoverer (siteA)
        cur.execute(
            "SELECT source_site FROM targets WHERE i2p_dns_name = ?",
            ("shared-target.i2p",),
        )
        row = cur.fetchone()
        assert row[0] == "siteA.i2p", (
            f"source_site should remain 'siteA.i2p'. Got '{row[0]}'"
        )

    @patch("src.integration.fetch_i2p")
    def test_deep_subdomain_in_source_site_preserved(self, mock_fetch, db):
        """Multi-level subdomains in the parent dns_name should be preserved
        verbatim in source_site (not truncated)."""
        known_links = ["deep-found.i2p"]
        mock_fetch.return_value = _make_mock_response(known_links)

        deep_parent = "forum.hidden.deep.example.i2p"
        ident_hash_hex = "dd" * 20
        probe_destination(
            ident_hash_hex=ident_hash_hex,
            i2p_dns_name=deep_parent,
            db=db,
            timeout=5.0,
        )

        cur = db._conn.cursor()
        cur.execute(
            "SELECT source_site FROM targets WHERE i2p_dns_name = ?",
            ("deep-found.i2p",),
        )
        row = cur.fetchone()
        assert row is not None
        assert row[0] == deep_parent, (
            f"source_site should preserve full subdomain. "
            f"Expected '{deep_parent}', got '{row[0]}'"
        )


class TestSourceSiteCrawlDepth:
    """Verify crawl_depth is recorded alongside source_site."""

    @patch("src.integration.fetch_i2p")
    def test_discovered_targets_get_crawl_depth(self, mock_fetch, db):
        """Targets discovered via probe_destination should have crawl_depth >= 1."""
        known_links = ["crawl-depth-target.i2p"]
        mock_fetch.return_value = _make_mock_response(known_links)

        ident_hash_hex = "ee" * 20
        probe_destination(
            ident_hash_hex=ident_hash_hex,
            i2p_dns_name="seed-parent.i2p",
            db=db,
            timeout=5.0,
        )

        cur = db._conn.cursor()
        cur.execute(
            "SELECT crawl_depth FROM targets WHERE i2p_dns_name = ?",
            ("crawl-depth-target.i2p",),
        )
        row = cur.fetchone()
        assert row is not None, "Discovered target missing from targets table"
        assert row[0] >= 1, (
            f"Discovered target should have crawl_depth >= 1, got {row[0]}"
        )
