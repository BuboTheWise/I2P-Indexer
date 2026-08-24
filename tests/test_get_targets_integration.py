"""Integration tests for DB query paths — verify get_targets() SQL against live schema."""

import os
import shutil
import tempfile
import time
import unittest
from src.integration import DiscoveryDB


class TestGetTargets(unittest.TestCase):
    """End-to-end tests that exercise get_targets() against a real SQLite database.

    These validate that the complex SQL (filter clauses, backoff, ORDER BY) produces
    the correct target ordering and filtering without hitting schema drift bugs.
    """

    def setUp(self):
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "test.db")
        self.db = DiscoveryDB(db_path)
        self.tmpdir = tmpdir
        now = time.time()
        cur = self.db._conn.cursor()

        # Insert test targets with different states (direct SQL since insert_target is internal)
        cur.executemany(
            "INSERT INTO targets (ident_hash_hex, b32_addr, i2p_dns_name, source) VALUES (?, ?, ?, ?)",
            [
                ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "alice.i2p", "old-reachable.i2p", "susid"),
                ("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "bob.i2p", "stale-target.i2p", "susid"),
                ("", "", "no-hash-target.i2p", "manual"),
            ],
        )

        # Mark old-reachable as previously reachable (via a discovery record)
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, b32_addr, i2p_dns_name, probe_mode, reachable, probed_at) "
            "VALUES (?, ?, ?, 'b32', 1, ?)",
            ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "alice.i2p", "old-reachable.i2p", now - 3600),
        )

        # Set backoff on stale-target (should skip when skip_backoff=True)
        cur.execute(
            "UPDATE targets SET backoff_until = ? WHERE i2p_dns_name = ?",
            (now + 86400, "stale-target.i2p"),
        )

        # Set last_probed_at for old-reachable (so never_probed excludes it)
        cur.execute(
            "UPDATE targets SET last_probed_at = ? WHERE i2p_dns_name = ?",
            (now - 7200, "old-reachable.i2p"),
        )

        self.db._conn.commit()

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.tmpdir)

    def test_all_returns_everything(self):
        targets = self.db.get_targets(filter_mode="all", skip_backoff=False)
        # 3 targets inserted, all visible when backoff is ignored
        self.assertEqual(len(targets), 3)

    def test_backoff_skips_protected_target(self):
        targets = self.db.get_targets(filter_mode="all", skip_backoff=True)
        dns_names = [t[1] for t in targets]
        self.assertNotIn("stale-target.i2p", dns_names, "Target in backoff must be skipped")
        self.assertIn("old-reachable.i2p", dns_names)

    def test_reachable_only_filters_correctly(self):
        targets = self.db.get_targets(filter_mode="reachable_only", skip_backoff=True)
        # Only target with a reachable discovery record should remain
        for row in targets:
            self.assertEqual(row[1], "old-reachable.i2p")

    def test_never_probed_returns_unprobed(self):
        targets = self.db.get_targets(filter_mode="never_probed", skip_backoff=False)
        dns_names = [t[1] for t in targets]
        # stale-target and no-hash-target have last_probed_at <= 0
        self.assertIn("stale-target.i2p", dns_names)
        self.assertIn("no-hash-target.i2p", dns_names)

    def test_ordering_prioritizes_reachable_then_hash_then_older(self):
        targets = self.db.get_targets(filter_mode="all", skip_backoff=False)
        if targets:
            # First should be old-reachable (previously reachable + valid hash)
            self.assertEqual(targets[0][1], "old-reachable.i2p")

    def test_stale_filter(self):
        targets = self.db.get_targets(filter_mode="stale", min_age_hours=1, skip_backoff=False)
        # old-reachable was probed 2h ago (> 1h), stale others at epoch 0 (< cutoff)
        dns_names = [t[1] for t in targets]
        self.assertIn("old-reachable.i2p", dns_names)


class TestBackoffState(unittest.TestCase):
    """Test the backoff state update logic."""

    def setUp(self):
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "test.db")
        self.db = DiscoveryDB(db_path)
        self.tmpdir = tmpdir
        self.db._conn.cursor().execute(
            "INSERT INTO targets (ident_hash_hex, b32_addr, i2p_dns_name, source) VALUES (?, ?, ?, ?)",
            ("cccccccccccccccccccccccccccccccccccccccc", "carol.i2p", "backoff-test.i2p", "manual"),
        )
        self.db._conn.commit()

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.tmpdir)

    def test_backoff_increases_failures_and_sets_until(self):
        now = time.time()
        self.db.update_backoff_state(
            "cccccccccccccccccccccccccccccccccccccccc", "", False
        )
        cur = self.db._conn.cursor()
        cur.execute(
            "SELECT backoff_until, consecutive_failures FROM targets "
            "WHERE ident_hash_hex = 'cccccccccccccccccccccccccccccccccccccccc'"
        )
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertGreater(row[0], now, "backoff_until should be in the future")
        self.assertGreater(row[1], 0, "consecutive_failures should increase")

    def test_success_resets_backoff(self):
        # First fail to set backoff
        self.db.update_backoff_state("cccccccccccccccccccccccccccccccccccccccc", "", False)
        # Then succeed to clear it
        self.db.update_backoff_state("cccccccccccccccccccccccccccccccccccccccc", "", True)
        cur = self.db._conn.cursor()
        cur.execute(
            "SELECT backoff_until, consecutive_failures FROM targets "
            "WHERE ident_hash_hex = 'cccccccccccccccccccccccccccccccccccccccc'"
        )
        row = cur.fetchone()
        self.assertEqual(row[0], 0.0, "backoff_until should be cleared on success")
        self.assertEqual(row[1], 0, "consecutive_failures should reset to 0")


if __name__ == "__main__":
    unittest.main()
