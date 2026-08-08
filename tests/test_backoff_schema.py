"""Tests for adaptive backoff schema columns in the targets table.

Verifies that consecutive_failures and backoff_until columns are created
correctly during DB initialization and migration, with proper defaults.
"""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.integration import DiscoveryDB


class TestBackoffSchema(unittest.TestCase):
    """Test that backoff metadata columns exist and have correct defaults."""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.db_fd)
        self.db = DiscoveryDB(self.db_path)

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_backoff_columns_exist_after_init(self):
        """Consecutive_failures and backoff_until columns exist after DB init."""
        cur = self.db._conn.cursor()
        cur.execute("PRAGMA table_info(targets)")
        col_names = {row[1] for row in cur.fetchall()}
        self.assertIn(
            "consecutive_failures",
            col_names,
            "targets table should have consecutive_failures column after init",
        )
        self.assertIn(
            "backoff_until",
            col_names,
            "targets table should have backoff_until column after init",
        )

    def test_default_values_correct(self):
        """New rows get correct default values (0 for failures, 0.0 for backoff)."""
        HASH_HEX = "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0"
        self.db.upsert_targets([(HASH_HEX, "default-test.i2p")])

        cur = self.db._conn.cursor()
        cur.execute(
            "SELECT consecutive_failures, backoff_until FROM targets WHERE ident_hash_hex = ?",
            (HASH_HEX,),
        )
        row = cur.fetchone()
        self.assertIsNotNone(row, "target should exist in database")
        self.assertEqual(
            row[0],
            0,
            "consecutive_failures should default to 0 for new targets",
        )
        self.assertEqual(
            row[1],
            0.0,
            "backoff_until should default to 0.0 for new targets",
        )

    def test_existing_rows_get_defaults_after_migration(self):
        """Rows inserted before migration receive default values via ALTER TABLE."""
        # Step 1: Close DiscoveryDB so we can manipulate the raw SQLite file.
        self.db.close()

        # Step 2: Open a raw connection and create the targets table WITHOUT
        # backoff columns — simulating an older DB that needs migration.
        raw_conn = sqlite3.connect(self.db_path)
        raw_cur = raw_conn.cursor()
        raw_cur.execute("DROP TABLE IF EXISTS targets")
        raw_cur.execute(
            """CREATE TABLE targets (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                ident_hash_hex   TEXT DEFAULT '',
                b32_addr         TEXT NOT NULL DEFAULT '',
                i2p_dns_name     TEXT DEFAULT '',
                last_probed_at   REAL DEFAULT 0,
                source           TEXT DEFAULT 'manual',
                UNIQUE(ident_hash_hex, i2p_dns_name)
            )"""
        )
        raw_cur.execute(
            """INSERT INTO targets (ident_hash_hex, b32_addr, i2p_dns_name)
               VALUES (?, 'legacy-target.b32.i2p', 'legacy.i2p')""",
            ("AA11BB22CC33DD44EE55FF66AA11BB22CC33DD44",),
        )
        raw_cur.execute(
            """INSERT INTO targets (ident_hash_hex, b32_addr, i2p_dns_name)
               VALUES (?, 'legacy-target2.b32.i2p', 'legacy2.i2p')""",
            ("11EE22DD33CC44BB55AA66EE22DD33CC44BB55AA",),
        )
        raw_conn.commit()
        raw_conn.close()

        # Step 3: Re-open with DiscoveryDB — _ensure_targets_columns runs the
        # ALTER TABLE migration and adds consecutive_failures / backoff_until.
        self.db = DiscoveryDB(self.db_path)

        cur = self.db._conn.cursor()
        # Verify columns now exist
        cur.execute("PRAGMA table_info(targets)")
        col_names = {row[1] for row in cur.fetchall()}
        self.assertIn("consecutive_failures", col_names)
        self.assertIn("backoff_until", col_names)

        # Verify ALL legacy rows received default values
        cur.execute(
            "SELECT consecutive_failures, backoff_until FROM targets"
        )
        rows = cur.fetchall()
        self.assertEqual(
            len(rows),
            2,
            "both legacy rows should still exist after migration",
        )
        for row in rows:
            self.assertEqual(
                row[0],
                0,
                "legacy consecutive_failures should default to 0 after ALTER TABLE",
            )
            self.assertEqual(
                row[1],
                0.0,
                "legacy backoff_until should default to 0.0 after ALTER TABLE",
            )

    def test_migration_is_idempotent(self):
        """Running _ensure_targets_columns twice does not duplicate columns."""
        cur = self.db._conn.cursor()
        cur.execute("PRAGMA table_info(targets)")
        all_cols = [row[1] for row in cur.fetchall()]
        # Count occurrences of backoff columns
        self.assertEqual(
            all_cols.count("consecutive_failures"),
            1,
            "consecutive_failures should appear exactly once",
        )
        self.assertEqual(
            all_cols.count("backoff_until"),
            1,
            "backoff_until should appear exactly once",
        )
        # Re-trigger migration by calling it again
        self.db._ensure_targets_columns()
        cur.execute("PRAGMA table_info(targets)")
        cols_after = [row[1] for row in cur.fetchall()]
        self.assertEqual(
            cols_after.count("consecutive_failures"),
            1,
            "consecutive_failures should still appear exactly one after re-run",
        )
        self.assertEqual(
            cols_after.count("backoff_until"),
            1,
            "backoff_until should still appear exactly once after re-run",
        )


if __name__ == "__main__":
    unittest.main()
