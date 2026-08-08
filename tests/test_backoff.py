"""Tests for adaptive backoff logic in I2P-Indexer."""

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.integration import (
    DiscoveryDB,
    _BACKOFF_INTERVALS,
    _compute_backoff_interval,
)


class TestBackoffIntervals(unittest.TestCase):
    """Test the exponential backoff interval calculator."""

    def test_zero_failures_returns_zero(self):
        self.assertEqual(_compute_backoff_interval(0), 0.0)

    def test_negative_failures_returns_zero(self):
        self.assertEqual(_compute_backoff_interval(-1), 0.0)

    def test_first_failure_one_minute(self):
        self.assertEqual(_compute_backoff_interval(1), 60)

    def test_second_failure_five_minutes(self):
        self.assertEqual(_compute_backoff_interval(2), 300)

    def test_third_failure_thirty_minutes(self):
        self.assertEqual(_compute_backoff_interval(3), 1800)

    def test_fourth_failure_two_hours(self):
        self.assertEqual(_compute_backoff_interval(4), 7200)

    def test_fifth_failure_twelve_hours(self):
        self.assertEqual(_compute_backoff_interval(5), 43200)

    def test_sixth_failure_capped_at_seven_days(self):
        self.assertEqual(_compute_backoff_interval(6), 604800)

    def test_large_failure_count_stays_at_cap(self):
        self.assertEqual(_compute_backoff_interval(100), 604800)

    def test_intervals_are_exponential(self):
        for i in range(1, len(_BACKOFF_INTERVALS)):
            # Each step is significantly larger than the previous
            if _BACKOFF_INTERVALS[i - 1] > 0:
                ratio = _BACKOFF_INTERVALS[i] / _BACKOFF_INTERVALS[i - 1]
                self.assertGreater(ratio, 1.0)

    def test_final_cap_is_seven_days(self):
        self.assertEqual(_BACKOFF_INTERVALS[-1], 7 * 24 * 3600)


class TestBackoffInDB(unittest.TestCase):
    """Test backoff columns are created and updated correctly in the DB."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.db_fd)
        self.db = DiscoveryDB(self.db_path)
        # Seed a target with a valid hash
        HASH_A = "A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9"
        self.db.upsert_targets([(HASH_A, "test-target.i2p")])

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_backoff_columns_exist(self):
        # Verify columns exist after initialization
        cur = self.db._conn.cursor()
        cur.execute("PRAGMA table_info(targets)")
        cols = {row[1] for row in cur.fetchall()}
        self.assertIn("consecutive_failures", cols)
        self.assertIn("backoff_until", cols)

    def test_default_values_are_zero(self):
        HASH_A = "A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9"
        cur = self.db._conn.cursor()
        cur.execute(
            "SELECT consecutive_failures, backoff_until FROM targets WHERE ident_hash_hex = ?",
            (HASH_A,),
        )
        row = cur.fetchone()
        self.assertEqual(row[0], 0)  # consecutive_failures defaults to 0
        self.assertEqual(row[1], 0.0)  # backoff_until defaults to 0

    def test_increment_on_failure(self):
        HASH_A = "A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9"
        cur = self.db._conn.cursor()

        # Simulate 3 consecutive failures
        for _ in range(3):
            self.db.update_backoff_state(HASH_A, "test-target.i2p", reachable=False)

        cur.execute(
            "SELECT consecutive_failures, backoff_until FROM targets WHERE ident_hash_hex = ?",
            (HASH_A,),
        )
        row = cur.fetchone()
        self.assertEqual(row[0], 3)  # 3 failures
        self.assertGreater(row[1], time.time())  # backoff is in the future

    def test_reset_on_success(self):
        HASH_A = "A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9"
        cur = self.db._conn.cursor()

        # Fail 2 times to set counter up
        for _ in range(2):
            self.db.update_backoff_state(HASH_A, "test-target.i2p", reachable=False)

        cur.execute(
            "SELECT consecutive_failures FROM targets WHERE ident_hash_hex = ?",
            (HASH_A,),
        )
        self.assertEqual(cur.fetchone()[0], 2)

        # Success resets counter
        self.db.update_backoff_state(HASH_A, "test-target.i2p", reachable=True)

        cur.execute(
            "SELECT consecutive_failures, backoff_until FROM targets WHERE ident_hash_hex = ?",
            (HASH_A,),
        )
        row = cur.fetchone()
        self.assertEqual(row[0], 0)  # reset to 0
        self.assertEqual(row[1], 0.0)  # backoff cleared

    def test_backoff_excludes_from_get_targets(self):
        """Targets with active backoff_until are excluded from the queue."""
        HASH_A = "A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9"
        HASH_B = "B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0"

        # Seed a second target that has no backoff
        self.db.upsert_targets([(HASH_B, "good-target.i2p")])

        # Put A into backoff with 5 consecutive failures
        for _ in range(5):
            self.db.update_backoff_state(HASH_A, "test-target.i2p", reachable=False)

        # get_targets with skip_backoff=True should exclude A
        targets = self.db.get_targets(skip_backoff=True)
        target_hashes = [t[0] for t in targets]
        self.assertNotIn(HASH_A, target_hashes)  # backoff blocked
        self.assertIn(HASH_B, target_hashes)     # still available

        # get_targets with skip_backoff=False should include both
        targets = self.db.get_targets(skip_backoff=False)
        target_hashes = [t[0] for t in targets]
        self.assertIn(HASH_A, target_hashes)
        self.assertIn(HASH_B, target_hashes)

    def test_dns_name_lookup_for_backoff(self):
        """Backoff updates work with DNS-only targets (no hash)."""
        # Insert a DNS-only target (empty hash)
        self.db.upsert_targets([("", "dns-only.i2p")])

        # Update via DNS name
        self.db.update_backoff_state("", "dns-only.i2p", reachable=False)

        cur = self.db._conn.cursor()
        cur.execute(
            "SELECT consecutive_failures, backoff_until FROM targets WHERE i2p_dns_name = ?",
            ("dns-only.i2p",),
        )
        row = cur.fetchone()
        self.assertEqual(row[0], 1)  # incremented by 1
        self.assertGreater(row[1], time.time())  # backoff set

    def test_backoff_skip_by_default(self):
        """Default behavior of get_targets() skips backed-off targets."""
        HASH_A = "A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9"

        # Put target in backoff
        for _ in range(3):
            self.db.update_backoff_state(HASH_A, "test-target.i2p", reachable=False)

        # Default call should skip the backed-off target
        targets = self.db.get_targets()
        target_hashes = [t[0] for t in targets]
        self.assertNotIn(HASH_A, target_hashes)


if __name__ == "__main__":
    unittest.main()
