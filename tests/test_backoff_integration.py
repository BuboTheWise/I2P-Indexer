"""Integration test: backoff strategy end-to-end with SQLite DB.

Verifies that --backoff-strategy exponential/fixed correctly sets backoff_until
on unreachable targets and that get_targets() respects backoff windows.

Tests use a temporary SQLite database and the actual update_backoff_state/get_targets
paths (no network calls needed).
"""

import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.integration import (
    BackoffStrategy,
    DiscoveryDB,
    _BACKOFF_INTERVALS,
    _FIXED_BACKOFF_SECONDS,
    _compute_backoff_interval,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_test_db() -> tuple[int, str]:  # (fd, path)
    """Create a fresh temp DB and return file descriptor + path."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return fd, path


class TestBackoffStrategyFixed(unittest.TestCase):
    """Verify the 'fixed' backoff strategy computes correct intervals."""

    def test_fixed_strategy_returns_constant_per_failure(self):
        """Fixed strategy: N failures => N * _FIXED_BACKOFF_SECONDS."""
        for n in range(1, 10):
            interval = _compute_backoff_interval(n, strategy=BackoffStrategy.FIXED)
            self.assertEqual(interval, float(n) * _FIXED_BACKOFF_SECONDS,
                             msg=f"fixed backoff for {n} failures should be {n*300}")

    def test_fixed_strategy_first_failure(self):
        self.assertAlmostEqual(
            _compute_backoff_interval(1, strategy=BackoffStrategy.FIXED),
            _FIXED_BACKOFF_SECONDS,
        )

    def test_fixed_strategy_three_failures(self):
        """Three failures → 3 × 300 = 900 seconds (15 minutes)."""
        self.assertAlmostEqual(
            _compute_backoff_interval(3, strategy=BackoffStrategy.FIXED),
            3 * _FIXED_BACKOFF_SECONDS,
        )

    def test_fixed_strategy_zero_failures(self):
        """Zero failures → no backoff."""
        self.assertEqual(
            _compute_backoff_interval(0, strategy=BackoffStrategy.FIXED),
            0.0,
        )


class TestBackoffStrategyIntegrationDB(unittest.TestCase):
    """Full integration: update_backoff_state writes correct backoff_until to DB.

    Each test gets its own temp SQLite database so there is no cross-test
    contamination. We verify:
      - both exponential and fixed strategies set backoff_until correctly
      - get_targets(skip_backoff=True) excludes backed-off targets
      - expired backoff windows allow targets through again
    """

    HASH_A = "A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9"
    HASH_B = "B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9C0"

    def setUp(self):
        _, self.db_path = _make_test_db()
        self.db = DiscoveryDB(self.db_path)
        self.db.upsert_targets([
            (self.HASH_A, "target-a.i2p"),
            (self.HASH_B, "target-b.i2p"),
        ])

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    # ------------------------------------------------------------------
    # Exponential strategy
    # ------------------------------------------------------------------

    def test_exponential_sets_backoff_until_correctly(self):
        """After 3 failures with exponential, backoff_until ≈ now + 1800s."""
        for _ in range(3):
            self.db.update_backoff_state(
                self.HASH_A, "target-a.i2p", reachable=False,
                backoff_strategy=BackoffStrategy.EXPONENTIAL,
            )

        now = time.time()
        cur = self.db._conn.cursor()
        cur.execute(
            "SELECT consecutive_failures, backoff_until FROM targets WHERE ident_hash_hex = ?",
            (self.HASH_A,),
        )
        row = cur.fetchone()
        self.assertEqual(row[0], 3)

        # backoff_until should be roughly now + 1800s (±5s tolerance for timing)
        expected_backoff = now + _BACKOFF_INTERVALS[2]  # index 2 → 1800s
        delta = abs(row[1] - expected_backoff)
        self.assertLess(delta, 5.0,
            msg=f"backoff_until={row[1]}, expected≈{expected_backoff}, diff={delta}")

    def test_exponential_grows_with_failures(self):
        """Verify backoff_until advances as failures accumulate."""
        backoffs = []
        for i in range(1, 6):
            self.db.update_backoff_state(
                self.HASH_A, "target-a.i2p", reachable=False,
                backoff_strategy=BackoffStrategy.EXPONENTIAL,
            )
            cur = self.db._conn.cursor()
            cur.execute(
                "SELECT backoff_until FROM targets WHERE ident_hash_hex = ?",
                (self.HASH_A,),
            )
            backoffs.append(cur.fetchone()[0])

        # Each subsequent backoff_until should be further in the future
        for i in range(len(backoffs) - 1):
            self.assertGreater(
                backoffs[i + 1], backoffs[i],
                msg=f"backoff not growing: {backoffs[i]} >= {backoffs[i+1]}",
            )

    # ------------------------------------------------------------------
    # Fixed strategy
    # ------------------------------------------------------------------

    def test_fixed_sets_backoff_until_correctly(self):
        """After 2 failures with fixed, backoff_until ≈ now + 600s (2 × 300s)."""
        for _ in range(2):
            self.db.update_backoff_state(
                self.HASH_A, "target-a.i2p", reachable=False,
                backoff_strategy=BackoffStrategy.FIXED,
            )

        now = time.time()
        cur = self.db._conn.cursor()
        cur.execute(
            "SELECT consecutive_failures, backoff_until FROM targets WHERE ident_hash_hex = ?",
            (self.HASH_A,),
        )
        row = cur.fetchone()
        self.assertEqual(row[0], 2)

        expected_backoff = now + 2 * _FIXED_BACKOFF_SECONDS
        delta = abs(row[1] - expected_backoff)
        self.assertLess(delta, 5.0,
            msg=f"backoff_until={row[1]}, expected≈{expected_backoff}, diff={delta}")

    def test_fixed_is_linear(self):
        """Fixed strategy grows linearly: each failure adds _FIXED_BACKOFF_SECONDS."""
        prev_backoff = 0
        for i in range(1, 6):
            self.db.update_backoff_state(
                self.HASH_A, "target-a.i2p", reachable=False,
                backoff_strategy=BackoffStrategy.FIXED,
            )
            cur = self.db._conn.cursor()
            cur.execute(
                "SELECT backoff_until FROM targets WHERE ident_hash_hex = ?",
                (self.HASH_A,),
            )
            cur_backoff = cur.fetchone()[0]
            # Each step should be ~300s more than the previous (within tolerance)
            gap = cur_backoff - prev_backoff if prev_backoff else 999
            self.assertGreater(gap, _FIXED_BACKOFF_SECONDS * 0.5,
                msg=f"fixed gap too small: {gap}")
            prev_backoff = cur_backoff

    # ------------------------------------------------------------------
    # get_targets() respects backoff windows
    # ------------------------------------------------------------------

    def test_get_targets_excludes_backed_off_exp(self):
        """get_targets(skip_backoff=True) excludes targets with active exponential backoff."""
        self.db.update_backoff_state(
            self.HASH_A, "target-a.i2p", reachable=False,
            backoff_strategy=BackoffStrategy.EXPONENTIAL,
        )

        targets = self.db.get_targets(skip_backoff=True)
        hashes = [t[0] for t in targets]
        self.assertNotIn(self.HASH_A, hashes)
        self.assertIn(self.HASH_B, hashes)  # other target still available

    def test_get_targets_excludes_backed_off_fixed(self):
        """get_targets(skip_backoff=True) excludes targets with active fixed backoff."""
        self.db.update_backoff_state(
            self.HASH_A, "target-a.i2p", reachable=False,
            backoff_strategy=BackoffStrategy.FIXED,
        )

        targets = self.db.get_targets(skip_backoff=True)
        hashes = [t[0] for t in targets]
        self.assertNotIn(self.HASH_A, hashes)
        self.assertIn(self.HASH_B, hashes)

    def test_get_targets_includes_expired_backoff(self):
        """When backoff_until has expired, target reappears in queue."""
        cur = self.db._conn.cursor()
        # Set backoff_until to 10 seconds in the past
        past_time = time.time() - 10
        cur.execute(
            "UPDATE targets SET backoff_until = ?, consecutive_failures = 3 WHERE ident_hash_hex = ?",
            (past_time, self.HASH_A),
        )
        self.db._conn.commit()

        # Now get_targets should include it again (backoff expired)
        targets = self.db.get_targets(skip_backoff=True)
        hashes = [t[0] for t in targets]
        self.assertIn(self.HASH_A, hashes)

    def test_get_targets_skip_backoff_false_includes_all(self):
        """skip_backoff=False includes backed-off targets regardless of strategy."""
        self.db.update_backoff_state(
            self.HASH_A, "target-a.i2p", reachable=False,
            backoff_strategy=BackoffStrategy.FIXED,
        )
        self.db.update_backoff_state(
            self.HASH_B, "target-b.i2p", reachable=False,
            backoff_strategy=BackoffStrategy.EXPONENTIAL,
        )

        targets = self.db.get_targets(skip_backoff=False)
        hashes = [t[0] for t in targets]
        self.assertIn(self.HASH_A, hashes)
        self.assertIn(self.HASH_B, hashes)

    # ------------------------------------------------------------------
    # Mixed strategies on same DB
    # ------------------------------------------------------------------

    def test_mixed_strategies_on_different_targets(self):
        """Two targets can be under different backoff strategies simultaneously."""
        # Target A: 3 failures with exponential → ~1800s
        for _ in range(3):
            self.db.update_backoff_state(
                self.HASH_A, "target-a.i2p", reachable=False,
                backoff_strategy=BackoffStrategy.EXPONENTIAL,
            )

        # Target B: 3 failures with fixed → 900s
        for _ in range(3):
            self.db.update_backoff_state(
                self.HASH_B, "target-b.i2p", reachable=False,
                backoff_strategy=BackoffStrategy.FIXED,
            )

        cur = self.db._conn.cursor()
        cur.execute(
            "SELECT ident_hash_hex, consecutive_failures, backoff_until FROM targets",
        )
        rows = {r[0]: (r[1], r[2]) for r in cur.fetchall()}

        # Both should have 3 failures each
        self.assertEqual(rows[self.HASH_A][0], 3)
        self.assertEqual(rows[self.HASH_B][0], 3)

        # Exponential backoff_until should be > fixed (1800s vs 900s from ~same time)
        exp_backoff = rows[self.HASH_A][1]
        fixed_backoff = rows[self.HASH_B][1]
        self.assertGreater(exp_backoff, fixed_backoff,
            msg=f"exponential backoff {exp_backoff} should exceed fixed {fixed_backoff}")

    # ------------------------------------------------------------------
    # Success resets backoff regardless of strategy
    # ------------------------------------------------------------------

    def test_success_resets_backoff_for_fixed_strategy(self):
        """A successful probe clears backoff_until even under fixed strategy."""
        self.db.update_backoff_state(
            self.HASH_A, "target-a.i2p", reachable=False,
            backoff_strategy=BackoffStrategy.FIXED,
        )
        self.db.update_backoff_state(
            self.HASH_A, "target-a.i2p", reachable=True,
            backoff_strategy=BackoffStrategy.FIXED,
        )

        cur = self.db._conn.cursor()
        cur.execute(
            "SELECT consecutive_failures, backoff_until FROM targets WHERE ident_hash_hex = ?",
            (self.HASH_A,),
        )
        row = cur.fetchone()
        self.assertEqual(row[0], 0)
        self.assertEqual(row[1], 0.0)


class TestDiscoverAddressesBackoffStrategy(unittest.TestCase):
    """Verify discover_addresses passes backoff_strategy to update_backoff_state.

    We mock probe_destination so no actual network calls happen, but the real
    DB and update_backoff_state path executes.
    """

    HASH = "A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F7A8B9"

    def setUp(self):
        _, self.db_path = _make_test_db()
        self.db = DiscoveryDB(self.db_path)
        self.db.upsert_targets([(self.HASH, "test.i2p")])

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def _make_failure_result(self):
        """Create a DiscoveryResult-like object that signifies failure."""
        result = MagicMock()
        result.reachable = False
        response_time_sec = getattr(result, 'response_time_sec', None)
        if response_time_sec is None:
            result.response_time_sec = 0.0
        return result

    def test_discover_addresses_uses_fixed_strategy(self):
        """discover_addresses with backoff_strategy='fixed' writes fixed intervals."""
        from src.integration import discover_addresses, probe_destination

        # Mock probe_destination to always fail
        with patch.object(
            sys.modules.get('src.integration', __import__('src.integration', fromlist=['probe_destination'])),
            'probe_destination',
            return_value=self._make_failure_result(),
        ):
            results = discover_addresses(
                db_instance=self.db,
                known_addrs=[self.HASH],
                backoff_strategy=BackoffStrategy.FIXED,
                probe_delay=0,
            )

        # After 1 failure with fixed strategy, backoff_until ≈ now + 300s
        cur = self.db._conn.cursor()
        cur.execute(
            "SELECT consecutive_failures, backoff_until FROM targets WHERE ident_hash_hex = ?",
            (self.HASH,),
        )
        row = cur.fetchone()
        self.assertEqual(row[0], 1)

        now = time.time()
        expected = now + _FIXED_BACKOFF_SECONDS
        delta = abs(row[1] - expected)
        self.assertLess(delta, 5.0,
            msg=f"discover did not use fixed strategy: backoff_until={row[1]}, expect≈{expected}")


if __name__ == "__main__":
    unittest.main()
