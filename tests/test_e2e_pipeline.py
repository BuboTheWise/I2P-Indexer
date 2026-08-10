"""End-to-end tests for the auto-generation pipeline.

Covers:
  1. Mocked flagged DB entries feeding into generate_extractors_pipeline()
  2. Generated plugins can_handle() verification against sample data
  3. File writing respects output paths (--out flag, ext_plugins dir)
  4. Validate harness catches bad fingerprints and produces suggestions

Convention: mock DiscoveryDB + fetch_i2p; use temp dirs for file I/O.
"""
from __future__ import annotations

import os
import pathlib
import sqlite3
import tempfile
from typing import List, Dict, Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_db_flagged(
    db_path: str,
    entries: List[Dict[str, Any]],
) -> None:
    """Create a test DB with flagged destinations in the discoveries table.

    Creates the full schema via DiscoveryDB.__init__ so the address_book view
    is present.  Each entry dict should have keys: hash_hex, b32_addr,
    dns_name (optional), content_type, title, status_code, reachable.
    """
    from src.integration import DiscoveryDB

    db = DiscoveryDB(db_path=db_path)
    conn = db._conn
    now = 1700000000.0
    for i, e in enumerate(entries):
        conn.execute(
            "INSERT INTO discoveries ("
            "ident_hash_hex, b32_addr, i2p_dns_name, probe_mode, reachable, "
            "status_code, content_type, title, needs_review, probed_at"
            ") VALUES (?, ?, ?, 'b32', 1, ?, ?, ?, 1, ?)",
            (
                e["hash_hex"],
                e.get("b32_addr", ""),
                e.get("dns_name", ""),
                e.get("status_code", 200),
                e.get("content_type", "text/html"),
                e.get("title", f"Test Site {i}"),
                now + i,
            ),
        )
    conn.commit()
    db.close()


def _make_flagged_list(
    count: int = 3,
) -> List[Dict[str, str]]:
    """Return a list of dicts consistent with get_flagged_destinations_with_hints()."""
    out = []
    for i in range(count):
        out.append({
            "hash_hex": f"{'a' * (39 - len(str(i)))}{i}",
            "dns_name": f"test{i}.i2p",
            "b32_addr": f"addr_{i}.b32.i2p",
            "content_type": "application/json" if i % 2 == 0 else "text/html; charset=utf-8",
            "title": f"Test Site {i}",
        })
    return out


def _mock_response(
    status: int = 200,
    body: bytes | str = b'{"status":"ok","items":[{"id":1,"name":"test"}]}',
    content_type: str = "application/json",
) -> MagicMock:
    """Build a mock I2P response object."""
    if isinstance(body, str):
        body = body.encode("utf-8")
    from src.i2p_proxy import ProxyBackend

    m = MagicMock()
    m.url = "http://test.i2p"
    m.status = status
    m.body = body
    m.text = body.decode("utf-8", errors="replace")
    m.headers = {"Content-Type": content_type}
    m.title.return_value = "Test Site"
    m.encoding = "utf-8"
    m.via = ProxyBackend.HTTP_PROXY
    m.elapsed = 1.0
    return m


# ---------------------------------------------------------------------------
# 1. generate_extractors_pipeline — mocked DB + fetch
# ---------------------------------------------------------------------------


class TestGenerateExtractorsPipeline:

    def _setup_flagged_db(self, tmp_path, count=3):
        """Create a temp SQLite DB with flagged destinations."""
        db_file = str(tmp_path / "test_indexer.db")
        entries = []
        for i in range(count):
            entries.append({
                "hash_hex": f"{'ff' * 19}{i:02x}",
                "dns_name": f"mysite{i}.i2p",
                "b32_addr": f"addr_{i}.b32.i2p",
                "content_type": "application/json" if i == 0 else "text/html; charset=utf-8",
                "title": f"Site {i}",
                "status_code": 200,
            })
        _make_db_flagged(db_file, entries)
        return db_file

    @patch("src.analyzer.fetch_i2p")
    def test_pipeline_processes_all_flagged(self, mock_fetch, tmp_path):
        """Pipeline iterates every flagged destination and produces results."""
        from src.analyzer import generate_extractors_pipeline

        db_file = self._setup_flagged_db(tmp_path, count=3)
        mock_fetch.return_value = _mock_response(200)

        with patch("src.integration.DEFAULT_DB_PATH", db_file):
            results = generate_extractors_pipeline(limit=None, dry_run=True)

        assert len(results) == 3
        for r in results:
            assert r.body_length > 0
            assert r.code_lines > 0

    @patch("src.analyzer.fetch_i2p")
    def test_pipeline_dry_run_does_not_write(self, mock_fetch, tmp_path):
        """dry_run=True produces results but writes no files to disk."""
        from src.analyzer import generate_extractors_pipeline

        db_file = self._setup_flagged_db(tmp_path, count=2)
        mock_fetch.return_value = _mock_response(200)

        with patch("src.integration.DEFAULT_DB_PATH", db_file):
            results = generate_extractors_pipeline(limit=None, dry_run=True)

        assert len(results) == 2
        for r in results:
            assert not r.written_path, "dry_run should not write files"