"""Tests for _do_reprobe feedback loop — needs_review flag clearing on success."""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure src/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.integration import (
    _do_reprobe,
    DiscoveryDB,
)


@pytest.fixture
def tmp_db_path(tmp_path):
    """A temporary on-disk SQLite database path."""
    return str(tmp_path / "reprober_test.db")


class TestReprobeFeedbackLoop:
    """Test the reprobe feedback loop.

    Flagged target gets reprobed with a mock successful probe, then needs_review
    is cleared and the entry appears in address_book without the review tag.
    """

    def _build_successful_mock_response(self):
        """Build a mock fetch_i2p response that HtmlExtractor classifies successfully."""
        # Body > 200 chars so it passes partial-extract quality check
        body_text = (
            "<html><head><title>Test I2P Blog</title></head>"
            "<body>"
            "<h1>Welcome to our I2P blog</h1>"
            "<p>This is a sample blog post about the invisible internet project "
            "and how anonymous networking works in practice today across all nodes.</p>"
            "<p>Another paragraph with enough text to pass quality checks and "
            "ensure extraction succeeds without triggering partial extract only "
            "flags on the destination record in the discovery database table here.</p>"
            "<div id='footer'>Powered by I2P hosting infrastructure system wide.</div>"
            "</body></html>"
        )
        raw_body = body_text.encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = raw_body
        mock_resp.text = body_text
        mock_resp.title.return_value = "Test I2P Blog"
        mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        return mock_resp

    def test_reprobe_clears_flag_on_success(self, tmp_db_path):
        """Create flagged discovery, mock successful probe, verify flag cleared."""
        ident_hash = "A" * 40
        dns_name = "test-blog.i2p"

        # Seed DB with a needs_review entry
        db = DiscoveryDB(db_path=tmp_db_path)
        db.record_discovery(
            ident_hash_hex=ident_hash,
            b32_addr="abjaiswiz5f6k37eppszfl6gqzwhmz3r.b32.i2p",
            i2p_dns_name=dns_name,
            probe_mode="b32",
            reachable=False,
            status_code=0,
            needs_review=True,
        )
        db.close()

        # Verify it is flagged before reprobe
        db = DiscoveryDB(db_path=tmp_db_path)
        flagged_before = db.get_flagged_destinations()
        assert len(flagged_before) == 1
        assert flagged_before[0][0] == ident_hash
        db.close()

        # Patch fetch_i2p to return success, patch DEFAULT_DB_PATH to temp DB
        mock_resp = self._build_successful_mock_response()
        with patch("src.integration.fetch_i2p", return_value=mock_resp), \
             patch("src.integration.DEFAULT_DB_PATH", tmp_db_path):
            _do_reprobe(limit=1, timeout=5.0)

        # Verify flag is cleared
        db = DiscoveryDB(db_path=tmp_db_path)
        flagged_after = db.get_flagged_destinations()
        assert len(flagged_after) == 0, "needs_review should be cleared after success"

        # Verify address_book shows the entry without review tag
        entries = db.address_book()
        found = [e for e in entries if e["ident_hash_hex"] == ident_hash]
        assert len(found) == 1, "Entry should exist in address_book"
        assert not found[0]["needs_review"], "needs_review must be 0 in address_book"
        db.close()

    def test_reprobe_keeps_flag_on_failure(self, tmp_db_path):
        """Flagged target with failed probe keeps needs_review set."""
        ident_hash = "B" * 40
        dns_name = "test-fail.i2p"

        # Seed DB
        db = DiscoveryDB(db_path=tmp_db_path)
        db.record_discovery(
            ident_hash_hex=ident_hash,
            b32_addr="b32fail.b32.i2p",
            i2p_dns_name=dns_name,
            probe_mode="b32",
            reachable=False,
            status_code=0,
            needs_review=True,
        )
        db.close()

        # Mock a failing response (502)
        mock_fail_resp = MagicMock()
        mock_fail_resp.status = 502
        mock_fail_resp.body = b""
        mock_fail_resp.text = ""
        mock_fail_resp.title.return_value = None
        mock_fail_resp.headers = {}

        with patch("src.integration.fetch_i2p", return_value=mock_fail_resp), \
             patch("src.integration.DEFAULT_DB_PATH", tmp_db_path):
            _do_reprobe(limit=1, timeout=5.0)

        # Flag should remain
        db = DiscoveryDB(db_path=tmp_db_path)
        flagged = db.get_flagged_destinations()
        assert len(flagged) == 1, "Flag should persist after failed probe"
        assert flagged[0][0] == ident_hash

        entries = db.address_book()
        found = [e for e in entries if e["ident_hash_hex"] == ident_hash]
        assert len(found) >= 1
        assert found[0]["needs_review"], "needs_review must stay set after failure"
        db.close()

    def test_reprobe_respects_limit(self, tmp_db_path):
        """Only the first N flagged destinations are reprobed when limit is set."""
        hashes = [f"{i:040x}" for i in range(3)]
        dns_names = [f"limit-{i}.test.i2p" for i in range(3)]

        db = DiscoveryDB(db_path=tmp_db_path)
        for h, name in zip(hashes, dns_names):
            db.record_discovery(
                ident_hash_hex=h,
                b32_addr=f"{h[:8]}.b32.i2p",
                i2p_dns_name=name,
                probe_mode="b32",
                reachable=False,
                status_code=0,
                needs_review=True,
            )
        db.close()

        mock_resp = self._build_successful_mock_response()

        with patch("src.integration.fetch_i2p", return_value=mock_resp), \
             patch("src.integration.DEFAULT_DB_PATH", tmp_db_path):
            _do_reprobe(limit=2, timeout=5.0)

        # Only 2 of 3 should have flags cleared
        db = DiscoveryDB(db_path=tmp_db_path)
        flagged = db.get_flagged_destinations()
        assert len(flagged) == 1, "Limit=2 leaves exactly 1 flag remaining"
        db.close()

    def test_reprobe_clears_flag_when_extractor_succeeds(self, tmp_db_path):
        """Full pipeline: fetch + extractor return content_type, flag gets cleared.

        Validates that when both reachable AND content_type are present on the
        probe result, clear_needs_review is invoked and the DB record reflects
        the cleared state via both get_flagged_destinations() and address_book().
        """
        ident_hash = "C" * 40
        dns_name = "clean-extractor.i2p"

        # Seed flags on this destination
        db = DiscoveryDB(db_path=tmp_db_path)
        db.record_discovery(
            ident_hash_hex=ident_hash,
            b32_addr="abjaiswiz5f6k37eppszfl6gqzwhmz3r.b32.i2p",
            i2p_dns_name=dns_name,
            probe_mode="b32",
            reachable=False,
            status_code=0,
            needs_review=True,
        )
        db.close()

        mock_resp = self._build_successful_mock_response()

        with patch("src.integration.fetch_i2p", return_value=mock_resp), \
             patch("src.integration.DEFAULT_DB_PATH", tmp_db_path):
            _do_reprobe(limit=1, timeout=5.0)

        # Check the discovery table directly for needs_review=0
        db = DiscoveryDB(db_path=tmp_db_path)
        conn = sqlite3.connect(tmp_db_path)
        row = conn.execute(
            "SELECT needs_review FROM discoveries WHERE ident_hash_hex = ?",
            (ident_hash,)
        ).fetchone()
        conn.close()
        assert row is not None, "Discovery record should still exist"
        assert row[0] == 0, f"needs_review should be 0, got {row[0]}"

        # Double-check via get_flagged_destinations
        flagged = db.get_flagged_destinations()
        assert len(flagged) == 0

        # And via address_book
        entries = db.address_book()
        found = [e for e in entries if e["ident_hash_hex"] == ident_hash]
        assert len(found) == 1
        assert not found[0]["needs_review"]
        db.close()
