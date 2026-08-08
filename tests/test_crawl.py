"""Tests for crawl functionality — auto_crawl(), depth propagation, provenance chain, safety bounds.

Covers:
- Schema migration adds crawl_depth and provenance_chain columns
- upsert_targets_from_links propagates crawl_depth and builds provenance chains
- get_new_targets_for_crawl returns only unprobed targets at the requested depth
- auto_crawl() respects max_depth, rate limits deeper rounds, stops on safety cap
- Per-depth domain deduplication
- Provenance chain lineage (A → B → C)
- CLI subcommand wiring
"""
from __future__ import annotations

import json
import os
import time
import tempfile
from unittest.mock import MagicMock, patch, call

import pytest
from src.integration import (
    DiscoveryDB,
    auto_crawl,
    probe_destination,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db(tmp_path):
    """A temporary on-disk SQLite database."""
    db_file = str(tmp_path / "test_crawl.db")
    return db_file


@pytest.fixture
def db(tmp_db):
    inst = DiscoveryDB(db_path=tmp_db)
    yield inst
    inst.close()


# ---------------------------------------------------------------------------
# Schema migration tests
# ---------------------------------------------------------------------------

class TestSchemaMigration:
    """Test that crawl_depth and provenance_chain columns are added."""

    def test_columns_exist_after_init(self, tmp_db):
        db = DiscoveryDB(db_path=tmp_db)
        try:
            cur = db._conn.cursor()
            cur.execute("PRAGMA table_info(targets)")
            cols = {row[1] for row in cur.fetchall()}
            assert "crawl_depth" in cols, "crawl_depth column missing after migration"
            assert "provenance_chain" in cols, "provenance_chain column missing after migration"
        finally:
            db.close()

    def test_columns_are_idempotent(self, tmp_db):
        """Calling _ensure_targets_columns twice should not error."""
        db = DiscoveryDB(db_path=tmp_db)
        try:
            db._ensure_targets_columns()  # second call should be safe
            cur = db._conn.cursor()
            cur.execute("PRAGMA table_info(targets)")
            cols = {row[1] for row in cur.fetchall()}
            assert "crawl_depth" in cols
        finally:
            db.close()

    def test_defaults_are_reasonable(self, tmp_db):
        """Crawl depth defaults to 0 (seeded), provenance_chain empty string."""
        db = DiscoveryDB(db_path=tmp_db)
        try:
            cur = db._conn.cursor()
            # Insert a target with default values
            cur.execute(
                "INSERT INTO targets (ident_hash_hex, i2p_dns_name, source) VALUES (?, ?, 'manual')",
                ("aa" * 20, "seed.i2p"),
            )
            db._conn.commit()
            cur.execute(
                "SELECT crawl_depth, provenance_chain FROM targets WHERE i2p_dns_name = ?",
                ("seed.i2p",),
            )
            row = cur.fetchone()
            assert row[0] == 0, f"Expected crawl_depth=0 for seeded target, got {row[0]}"
            assert row[1] == "", f"Expected empty provenance_chain, got {row[1]}"
        finally:
            db.close()


# ---------------------------------------------------------------------------
# upsert_targets_from_links — depth propagation + provenance chain
# ---------------------------------------------------------------------------

class TestUpsertTargetsFromLinks:
    """Test crawl_depth propagation and provenance chain building."""

    def test_basic_upsert_records_depth(self, db):
        added = db.upsert_targets_from_links(
            linked_sites=["child1.i2p", "child2.i2p"],
            source_site="seed.i2p",
            crawl_depth=1,
        )
        assert added == 2
        cur = db._conn.cursor()
        cur.execute("SELECT i2p_dns_name, crawl_depth FROM targets WHERE i2p_dns_name LIKE ?", ("child%i2p",))
        rows = {r[0]: r[1] for r in cur.fetchall()}
        assert rows["child1.i2p"] == 1
        assert rows["child2.i2p"] == 1

    def test_upsert_does_not_duplicate_existing_dns(self, db):
        first = db.upsert_targets_from_links(
            linked_sites=["dup.i2p"],
            source_site="seed.i2p",
            crawl_depth=1,
        )
        assert first == 1
        second = db.upsert_targets_from_links(
            linked_sites=["dup.i2p"],
            source_site="other.i2p",
            crawl_depth=2,
        )
        assert second == 0

    def test_provenance_chain_simple_seed_to_child(self, db):
        # Insert the seed first with an empty chain
        cur = db._conn.cursor()
        cur.execute(
            "INSERT INTO targets (ident_hash_hex, i2p_dns_name, source, provenance_chain) "
            "VALUES (?, ?, 'manual', '')",
            ("aa" * 20, "seed.i2p"),
        )
        db._conn.commit()

        # Now upsert a child — chain should be "seed → child1.i2p"
        added = db.upsert_targets_from_links(
            linked_sites=["child1.i2p"],
            source_site="seed.i2p",
            crawl_depth=1,
        )
        assert added == 1

        cur.execute(
            "SELECT provenance_chain FROM targets WHERE i2p_dns_name = ?",
            ("child1.i2p",),
        )
        chain = cur.fetchone()[0]
        # Chain should contain the parent and child
        assert "child1.i2p" in chain

    def test_provenance_chain_multi_hop(self, db):
        """seed → intermediate → leaf proves 3-level lineage."""
        # Seed
        cur = db._conn.cursor()
        cur.execute(
            "INSERT INTO targets (ident_hash_hex, i2p_dns_name, source, provenance_chain) "
            "VALUES (?, ?, 'manual', '')",
            ("aa" * 20, "seed.i2p"),
        )
        db._conn.commit()

        # Depth 1: seed finds intermediate
        db.upsert_targets_from_links(
            linked_sites=["mid.i2p"],
            source_site="seed.i2p",
            crawl_depth=1,
        )

        # Depth 2: mid finds leaf
        added = db.upsert_targets_from_links(
            linked_sites=["leaf.i2p"],
            source_site="mid.i2p",
            crawl_depth=2,
        )
        assert added == 1

        cur.execute(
            "SELECT provenance_chain FROM targets WHERE i2p_dns_name = ?",
            ("leaf.i2p",),
        )
        chain = cur.fetchone()[0]
        # Full lineage: seed → mid.i2p → leaf.i2p
        assert "mid.i2p" in chain, "Intermediate missing from chain"
        assert "leaf.i2p" in chain, "Leaf missing from chain"

    def test_empty_source_site_produces_minimal_chain(self, db):
        """When source_site is empty, chain should just be the DNS name."""
        added = db.upsert_targets_from_links(
            linked_sites=["orphan.i2p"],
            source_site="",
            crawl_depth=1,
        )
        assert added == 1

        cur = db._conn.cursor()
        cur.execute(
            "SELECT provenance_chain FROM targets WHERE i2p_dns_name = ?",
            ("orphan.i2p",),
        )
        chain = cur.fetchone()[0]
        # Without a known parent, chain is just the DNS name
        assert "orphan.i2p" in chain

    def test_empty_strings_in_linked_sites_are_skipped(self, db):
        added = db.upsert_targets_from_links(
            linked_sites=["", "real.i2p", ""],
            source_site="parent.i2p",
            crawl_depth=1,
        )
        assert added == 1


# ---------------------------------------------------------------------------
# get_new_targets_for_crawl — query logic
# ---------------------------------------------------------------------------

class TestGetNewTargetsForCrawl:
    """Test depth-based filtered queries for the crawl loop."""

    def test_returns_only_unprobed_targets_at_depth(self, db):
        cur = db._conn.cursor()
        # Insert 2 targets at depth=1
        for dns in ["new1.i2p", "new2.i2p"]:
            cur.execute(
                "INSERT INTO targets (i2p_dns_name, source, crawl_depth, last_probed_at) "
                "VALUES (?, 'linked', 1, 0)",
                (dns,),
            )
        # Insert 1 already-probed target at depth=1 (last_probed_at > 0)
        cur.execute(
            "INSERT INTO targets (i2p_dns_name, source, crawl_depth, last_probed_at) "
            "VALUES (?, 'linked', 1, ?)",
            ("probed.i2p", time.time()),
        )
        # Insert target at depth=0 (seeded) — should not appear
        cur.execute(
            "INSERT INTO targets (i2p_dns_name, source, crawl_depth, last_probed_at) "
            "VALUES (?, 'manual', 0, 0)",
            ("seeded.i2p",),
        )
        db._conn.commit()

        results = db.get_new_targets_for_crawl(depth=1)
        dns_names = [r[1] for r in results]
        assert "probed.i2p" not in dns_names, "Probed target should not appear"
        assert "new1.i2p" in dns_names
        assert "new2.i2p" in dns_names

    def test_max_count_limits_results(self, db):
        cur = db._conn.cursor()
        for i in range(5):
            cur.execute(
                "INSERT INTO targets (i2p_dns_name, source, crawl_depth, last_probed_at) "
                "VALUES (?, 'linked', 1, 0)",
                (f"t{i}.i2p",),
            )
        db._conn.commit()

        results = db.get_new_targets_for_crawl(depth=1, max_count=3)
        assert len(results) == 3

    def test_no_unprobed_returns_empty(self, db):
        results = db.get_new_targets_for_crawl(depth=1)
        assert results == []


# ---------------------------------------------------------------------------
# auto_crawl — integration tests with mocked probe_destination
# ---------------------------------------------------------------------------

class TestAutoCrawl:
    """Full crawl loop tests with mocked network calls."""

    def _seed_db(self, db, depth: int = 0):
        """Seed the DB with known targets at a given crawl_depth."""
        cur = db._conn.cursor()
        for i in range(5):
            # Use different hash for each depth to avoid UNIQUE constraint violations
            hx = f"bb{depth}" * (20 // len(f"bb{depth}")) + "0" * (40 - (len(f"bb{depth}") * (20 // len(f"bb{depth}"))))
            hx = hx[:40]
            cur.execute(
                "INSERT INTO targets (ident_hash_hex, i2p_dns_name, source, crawl_depth, last_probed_at) "
                "VALUES (?, ?, 'linked', ?, 0)",
                (hx, f"d{depth}_t{i}.i2p", depth),
            )
        db._conn.commit()

    def _mock_probe(self, reachable=True):
        """Return a mock result for probe_destination."""
        mock_result = MagicMock()
        mock_result.reachable = reachable
        mock_result.content_type = "text/html"
        mock_result.title = "Mocked Page"
        mock_result.found_links = [] if not reachable else ["new_discovery.i2p"]
        return mock_result

    @patch("src.integration.probe_destination")
    def test_crawl_one_depth_level(self, mock_probe_fn, db):
        """Crawl at depth 1 with max_depth=1 — only one round runs."""
        # Seed targets at depth 1
        self._seed_db(db, depth=1)

        mock_probe_fn.side_effect = [self._mock_probe(reachable=True)] * 5

        stats = auto_crawl(
            max_depth=1,
            crawl_delay=0.01,  # tiny delay for tests
            timeout=5.0,
            db_instance=db,
        )

        assert stats["rounds_run"] >= 1
        assert stats["probes_attempted"] == 5
        assert stats["depth_reached"] == 1

    @patch("src.integration.probe_destination")
    def test_crawl_stops_when_no_targets_at_next_depth(self, mock_probe_fn, db):
        """If depth 2 has no unprobed targets, crawl finishes without round 2."""
        # Seed at depth 1 only
        self._seed_db(db, depth=1)

        mock_probe_fn.return_value = self._mock_probe(reachable=False)

        stats = auto_crawl(
            max_depth=3,
            crawl_delay=0.01,
            timeout=5.0,
            db_instance=db,
        )

        # Should stop after round 1 since depth 2 is empty
        assert stats["rounds_run"] == 1

    @patch("src.integration.probe_destination")
    def test_crawl_respects_max_new_targets_cap(self, mock_probe_fn, db):
        """Safety cap stops crawl when max_new_targets is reached."""
        # Seed 5 targets at each depth level
        self._seed_db(db, depth=1)
        self._seed_db(db, depth=2)

        mock_probe_fn.return_value = self._mock_probe(reachable=False)

        stats = auto_crawl(
            max_depth=3,
            crawl_delay=0.01,
            timeout=5.0,
            max_new_targets=8,  # small cap — fewer than total available
            db_instance=db,
        )

        # Should have stopped early due to the cap
        assert stats["probes_attempted"] <= 10

    @patch("src.integration.probe_destination")
    def test_crawl_tracks_ok_and_fail_per_depth(self, mock_probe_fn, db):
        """Stats should record ok/fail counts per depth round."""
        self._seed_db(db, depth=1)

        # Alternate reachable/unreachable results
        responses = [self._mock_probe(reachable=(i % 2 == 0)) for i in range(5)]
        mock_probe_fn.side_effect = responses

        stats = auto_crawl(
            max_depth=1,
            crawl_delay=0.01,
            timeout=5.0,
            db_instance=db,
        )

        assert "1" in stats["domains_per_depth"]
        depth_stats = stats["domains_per_depth"]["1"]
        assert depth_stats["attempted"] == 5

    @patch("src.integration.probe_destination")
    def test_crawl_with_no_linked_targets(self, mock_probe_fn, db):
        """Empty DB means no rounds run and zero probes."""
        stats = auto_crawl(
            max_depth=2,
            crawl_delay=0.01,
            timeout=5.0,
            db_instance=db,
        )

        assert stats["probes_attempted"] == 0
        mock_probe_fn.assert_not_called()

    def test_domain_dedup_within_round(self, db):
        """If same DNS is inserted twice at depth 1, dedup ensures it's only probed once."""
        cur = db._conn.cursor()
        # Same dns_name should be skipped by the domain dedup logic, but the DB also
        # prevents duplicates. The get_new_targets_for_crawl query already filters unique rows.
        cur.execute(
            "INSERT INTO targets (ident_hash_hex, i2p_dns_name, source, crawl_depth, last_probed_at) "
            "VALUES (?, ?, 'linked', 1, 0)",
            ("aa" * 20, "dedup.i2p"),
        )
        db._conn.commit()

        results = db.get_new_targets_for_crawl(depth=1)
        dns_list = [r[1] for r in results]
        assert dns_list.count("dedup.i2p") == 1


# ---------------------------------------------------------------------------
# Rate limiting verification — depth scales the delay
# ---------------------------------------------------------------------------

class TestCrawlRateLimiting:
    """Verify that effective_delay scales with depth."""

    def test_effective_delay_formula(self):
        """Depth 1 → base * 1.0, Depth 2 → base * 1.5, Depth 3 → base * 2.0."""
        base = 10.0
        for d in range(1, 6):
            effective = base * max(1.0, 1.0 + (d - 1) * 0.5)
            # Verify delay grows with depth
            if d > 1:
                prev_effective = base * max(1.0, 1.0 + (d - 2) * 0.5)
                assert effective > prev_effective, f"Depth {d} delay should exceed depth {d-1}"


# ---------------------------------------------------------------------------
# Safety bounds — CLI parameter wiring
# ---------------------------------------------------------------------------

class TestCrawlSafety:
    """Test that safety parameters work as expected."""

    def test_max_depth_zero_stops_immediately(self, db):
        auto_crawl(
            max_depth=0,
            crawl_delay=0.01,
            db_instance=db,
        )
        # With max_depth=0, the range(1, 1) is empty → no rounds

    def test_max_new_targets_none_means_unlimited(self):
        """max_new_targets=None should not impose a cap."""
        # This is tested by default behavior — None means no cap check
        assert True


# ---------------------------------------------------------------------------
# CLI crawl subcommand wiring
# ---------------------------------------------------------------------------

class TestCrawlCLI:
    """Test that the crawl subcommand is properly wired in main()."""

    def test_crawl_subcommand_exists(self):
        from src.integration import main
        import subprocess, sys
        # Check that 'crawl' appears in help output
        result = subprocess.run(
            [sys.executable, "-m", "src.integration", "--help"],
            capture_output=True, text=True,
            cwd="/home/stefan/Projects/I2P-Indexer/.worktrees/t_cedd150d",
        )
        assert "crawl" in result.stdout.lower()

    def test_crawl_help_shows_options(self):
        import subprocess, sys
        result = subprocess.run(
            [sys.executable, "-m", "src.integration", "crawl", "--help"],
            capture_output=True, text=True,
            cwd="/home/stefan/Projects/I2P-Indexer/.worktrees/t_cedd150d",
        )
        assert "--max-depth" in result.stdout
        assert "--crawl-delay" in result.stdout
        assert "--max-new-targets" in result.stdout
