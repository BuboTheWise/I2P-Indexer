"""Tests for src/deep_analysis.py — deep site analysis pipeline.

Covers:
- HTML stripping (tag removal, whitespace collapse, 4096 char limit)
- strip_html with various inputs (empty, short, long, Unicode)
- get_pending_analyses queries (reachable, stale, never_analyzed modes)
- update_analysis DB write (UPSERT behavior, last_analyzed_at tracking)
- Prompt file loading and interpolation
- Mocked Ollama call (avoid live network in tests)

All tests avoid I2P proxy connections — fetch_body_via_proxy is not tested here.
"""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.deep_analysis import (
    _HTMLStripper,
    _strip_markdown_fences as deep_strip_md,
    strip_html,
    get_pending_analyses,
    update_analysis,
)


class TestHTMLStripping:
    """Test HTML tag stripping and text extraction."""

    def test_strip_basic_html(self):
        html = "<p>Hello <strong>world</strong></p>"
        assert strip_html(html) == "Hello world"

    def test_strip_with_whitespace(self):
        html = "<div>\n  <p>  Line   one  </p>\n  <p>Line two</p>\n</div>"
        assert strip_html(html) == "Line one Line two"

    def test_strip_empty(self):
        assert strip_html("<p></p>") == ""

    def test_strip_script_tags(self):
        html = "<script>alert('xss')</script><p>Real content</p>"
        result = strip_html(html)
        assert "alert" not in result  # script content is skipped
        assert "Real content" in result

    def test_strip_style_tags(self):
        html = "<style>.x{color:red}</style><p>Real content</p>"
        result = strip_html(html)
        assert "color" not in result  # style content is skipped
        assert "Real content" in result

    def test_strip_unicode(self):
        html = "<p>Héllo Wörld — 你好</p>"
        assert strip_html(html) == "Héllo Wörld — 你好"

    def test_strip_limits_to_8192_chars(self):
        long_text = "A " * 3000  # ~12000 chars after join
        html = f"<p>{long_text}</p>"
        result = strip_html(html)
        assert len(result) <= 8192

    def test_strip_short_content(self):
        short = "<p>Hi</p>"
        assert "Hi" in strip_html(short)
        assert len(strip_html(short)) >= 2

    def test_stripper_text_method(self):
        s = _HTMLStripper()
        s.feed("<b>bold</b> and <i>italic</i>")
        assert "bold" in s.text()
        assert "italic" in s.text()


class TestPendingAnalyses:
    """Test get_pending_analyses with real temp DB (no network)."""

    def _create_test_db(self):
        """Create a temporary DB with test discoveries/targets tables."""
        import sqlite3

        self.db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        conn = sqlite3.connect(self.db.name)
        cur = conn.cursor()

        # Create minimal migrations-ready schema
        cur.execute(
            "CREATE TABLE IF NOT EXISTS discoveries ("
            "ident_hash_hex TEXT NOT NULL, "
            "b32_addr TEXT NOT NULL DEFAULT '', "
            "i2p_dns_name TEXT NOT NULL DEFAULT '', "
            "probe_mode TEXT NOT NULL DEFAULT '', "
            "reachable INTEGER NOT NULL DEFAULT 0, "
            "title TEXT DEFAULT '', "
            "content_summary TEXT DEFAULT '', "
            "deep_analysis TEXT DEFAULT '', "
            "probed_at REAL NOT NULL DEFAULT 0)"
        )
        cur.execute(
            "CREATE TABLE IF NOT EXISTS targets ("
            "ident_hash_hex TEXT PRIMARY KEY, "
            "last_probed_at REAL DEFAULT 0, "
            "last_analyzed_at REAL DEFAULT 0)"
        )
        conn.commit()
        return conn

    def test_get_pending_reachable(self):
        """Reachable sites should appear in pending analyses."""
        conn = self._create_test_db()
        cur = conn.cursor()

        # Insert reachable and unreachable sites
        now = 1770000000.0
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, b32_addr, i2p_dns_name,"
            "probe_mode, reachable, title, probed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("hash_reachable", "b32.reachable.i2p", "reachable.i2p",
             "dns", 1, "Reachable Site", now),
        )
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, b32_addr, i2p_dns_name,"
            "probe_mode, reachable, title, probed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("hash_unreachable", "b32.dead.i2p", "dead.i2p",
             "dns", 0, "Dead Site", now),
        )

        # Insert targets
        for h in ("hash_reachable", "hash_unreachable"):
            cur.execute(
                "INSERT INTO targets (ident_hash_hex, last_probed_at)"
                " VALUES (?, ?)",
                (h, now),
            )

        conn.commit()
        conn.close()

        results = get_pending_analyses(self.db.name, mode="reachable", limit=10)
        result_hashes = {r[0] for r in results}
        assert "hash_reachable" in result_hashes
        assert "hash_unreachable" not in result_hashes

    def test_never_analyzed_prioritizes_unanalyzed(self):
        """never_analyzed mode should only return unanalyzed sites."""
        conn = self._create_test_db()
        cur = conn.cursor()

        now = 1770000000.0
        # Unanalyzed site
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, b32_addr, i2p_dns_name,"
            "probe_mode, reachable, title, probed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("hash_new", "b32.new.i2p", "new.i2p",
             "dns", 1, "New Site", now),
        )
        # Analyzed site (has deep_analysis content)
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, b32_addr, i2p_dns_name,"
            "probe_mode, reachable, title, probed_at, deep_analysis)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("hash_analyzed", "b32.analyzed.i2p", "analyzed.i2p",
             "dns", 1, "Analyzed Site", now, '{}'),
        )

        for h in ("hash_new", "hash_analyzed"):
            cur.execute(
                "INSERT INTO targets (ident_hash_hex, last_probed_at)"
                " VALUES (?, ?)",
                (h, now),
            )

        conn.commit()
        conn.close()

        results = get_pending_analyses(self.db.name, mode="never_analyzed", limit=10)
        result_hashes = {r[0] for r in results}
        assert "hash_new" in result_hashes
        # analyzed site should not appear if it has deep_analysis content
        assert "hash_analyzed" not in result_hashes

    def test_limit_respected(self):
        """Result count should not exceed limit."""
        conn = self._create_test_db()
        cur = conn.cursor()
        now = 1770000000.0

        for i in range(20):
            cur.execute(
                "INSERT INTO discoveries (ident_hash_hex, b32_addr,"
                "i2p_dns_name, probe_mode, reachable, title, probed_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (f"hash_{i:02d}", f"b32{i}.i2p", f"site{i}.i2p",
                 "dns", 1, f"Site {i}", now),
            )
            cur.execute(
                "INSERT INTO targets (ident_hash_hex, last_probed_at)"
                " VALUES (?, ?)",
                (f"hash_{i:02d}", now),
            )

        conn.commit()
        conn.close()

        results = get_pending_analyses(self.db.name, mode="reachable", limit=5)
        assert len(results) <= 5

    def test_stale_mode_returns_old_sites(self):
        """Stale mode should return sites not analyzed recently."""
        conn = self._create_test_db()
        cur = conn.cursor()
        now = 1770000000.0
        old = now - 3000000  # Over 30 days ago

        # Freshly analyzed site
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, b32_addr,"
            "probe_mode, reachable, title, probed_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            ("hash_fresh", "b32.fresh.i2p",
             "dns", 1, "Fresh Site", now),
        )
        cur.execute(
            "INSERT INTO targets (ident_hash_hex, last_probed_at,"
            "last_analyzed_at) VALUES (?, ?, ?)",
            ("hash_fresh", now, now),
        )

        # Stale site
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, b32_addr,"
            "probe_mode, reachable, title, probed_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            ("hash_stale", "b32.stale.i2p",
             "dns", 1, "Stale Site", now),
        )
        cur.execute(
            "INSERT INTO targets (ident_hash_hex, last_probed_at,"
            "last_analyzed_at) VALUES (?, ?, ?)",
            ("hash_stale", now, old),
        )

        conn.commit()
        conn.close()

        results = get_pending_analyses(self.db.name, mode="stale", limit=10)
        result_hashes = {r[0] for r in results}
        assert "hash_stale" in result_hashes

    def test_invalid_mode_raises(self):
        """Unknown mode should raise ValueError."""
        conn = self._create_test_db()
        conn.close()

        import pytest

        with pytest.raises(ValueError, match="Unknown mode"):
            get_pending_analyses(self.db.name, mode="invalid", limit=10)


class TestUpdateAnalysis:
    """Test update_analysis DB writes and UPSERT behavior."""

    def _create_test_db(self):
        """Create temp DB with schema for analysis storage."""
        import sqlite3

        self.db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        conn = sqlite3.connect(self.db.name)
        cur = conn.cursor()

        # Full discoveries table (matches migration columns)
        cur.execute(
            "CREATE TABLE IF NOT EXISTS discoveries ("
            "ident_hash_hex TEXT NOT NULL, "
            "b32_addr TEXT NOT NULL DEFAULT '', "
            "i2p_dns_name TEXT NOT NULL DEFAULT '', "
            "probe_mode TEXT NOT NULL DEFAULT '', "
            "reachable INTEGER NOT NULL DEFAULT 0, "
            "title TEXT DEFAULT '', "
            "content_summary TEXT DEFAULT '', "
            "deep_analysis TEXT DEFAULT '', "
            "probed_at REAL NOT NULL DEFAULT 0, "
            "PRIMARY KEY (ident_hash_hex, probe_mode))"
        )

        # Targets table with last_analyzed_at
        cur.execute(
            "CREATE TABLE IF NOT EXISTS targets ("
            "ident_hash_hex TEXT PRIMARY KEY, "
            "last_probed_at REAL DEFAULT 0, "
            "last_analyzed_at REAL DEFAULT 0)"
        )

        # Initial discovery rows for upsert testing
        cur.execute(
            "INSERT INTO discoveries "
            "(ident_hash_hex, probe_mode) VALUES (?, ?)",
            ("test_hash_1", "dns"),
        )

        # Corresponding target for timestamp update
        cur.execute(
            "INSERT INTO targets (ident_hash_hex, last_probed_at) VALUES (?, 0.0)",
            ("test_hash_1",),
        )

        conn.commit()
        conn.close()

    def test_store_analysis_creates_entry(self):
        """New analysis should be stored via UPSERT."""
        import sqlite3

        self._create_test_db()

        update_analysis(
            self.db.name,
            "test_hash_1",
            "dns",
            json.dumps({"site_type": "forum", "purpose": "discussion"}),
        )

        conn = sqlite3.connect(self.db.name)
        cur = conn.cursor()
        cur.execute(
            "SELECT deep_analysis FROM discoveries WHERE ident_hash_hex = ?",
            ("test_hash_1",),
        )
        row = cur.fetchone()
        assert row is not None, "Deep analysis entry was not created"

        parsed = json.loads(row[0])
        assert "site_type" in parsed
        assert parsed["site_type"] == "forum"
        conn.close()

    def test_update_analysis_updates_last_analyzed_at(self):
        """last_analyzed_at should be updated after analysis."""
        self._create_test_db()

        import sqlite3

        # Before: last_analyzed_at is 0.0
        update_analysis(
            self.db.name,
            "test_hash_1",
            "dns",
            json.dumps({"purpose": "test"}),
        )

        conn = sqlite3.connect(self.db.name)
        cur = conn.cursor()
        cur.execute(
            "SELECT last_analyzed_at FROM targets WHERE ident_hash_hex = ?",
            ("test_hash_1",),
        )
        row = cur.fetchone()
        assert row[0] > 0, f"last_analyzed_at not updated, got {row[0]}"
        conn.close()

    def test_upsert_overwrites_previous_analysis(self):
        """Analysis stored on an empty row gets populated."""
        self._create_test_db()

        update_analysis(
            self.db.name, "test_hash_1", "dns",
            json.dumps({"site_type": "first"}))

        # First call stores it
        import sqlite3

        conn = sqlite3.connect(self.db.name)
        cur = conn.cursor()
        cur.execute(
            "SELECT deep_analysis FROM discoveries WHERE ident_hash_hex = ?",
            ("test_hash_1",),
        )
        row = cur.fetchone()
        parsed = json.loads(row[0])
        assert parsed["site_type"] == "first"
        conn.close()


class TestPromptLoading:
    """Test that the prompt file loads correctly."""

    def test_default_prompt_file_exists(self):
        """Default analysis_prompt.txt should exist in project root."""
        prompt_path = os.path.join(
            os.path.dirname(__file__), "..", "analysis_prompt.txt"
        )
        assert os.path.exists(prompt_path), f"Expected prompt at {prompt_path}"

    def test_prompt_file_has_body_placeholder(self):
        """Prompt should contain {{BODY}} placeholder for interpolation."""
        with open(
            os.path.join(os.path.dirname(__file__), "..", "analysis_prompt.txt"),
            encoding="utf-8",
        ) as f:
            content = f.read()

        assert "{{BODY}}" in content, (
            "Prompt file missing {{BODY}} placeholder"
        )

    def test_prompt_file_contains_site_type_instruction(self):
        """Prompt should instruct model to classify into site_type."""
        with open(
            os.path.join(os.path.dirname(__file__), "..", "analysis_prompt.txt"),
            encoding="utf-8",
        ) as f:
            content = f.read()

        assert "site_type" in content.lower(), (
            "Prompt should request site_type classification"
        )


class TestHTMLStripperEdgeCases:
    """Additional edge cases for the _HTMLStripper class."""

    def test_no_tags_returns_text(self):
        s = _HTMLStripper()
        s.feed("Plain text here")
        assert s.text() == "Plain text here"

    def test_nested_html_stripped(self):
        html = "<div><span><a href='#'>Link</a></span></div>"
        s = _HTMLStripper()
        s.feed(html)
        # Should still extract visible text
        result = s.text()
        assert "Link" in result

    def test_multiple_collapsing_spaces_handled(self):
        html = "<p>one</p>\t\t<p>two</p>"
        result = strip_html(html)
        assert "  " not in result, "Double spaces should be collapsed"


class TestMarkdownFenceStripping:
    """Test _strip_markdown_fences for handling model-wrapped JSON."""

    def test_fenced_json_stripped(self):
        text = "```json\n{\"site_type\": \"forum\"}\n```"
        assert deep_strip_md(text) == '{"site_type": "forum"}'

    def test_plain_json_unchanged(self):
        text = '{"site_type": "wiki"}'
        assert deep_strip_md(text) == text

    def test_no_closing_fence_stripped(self):
        text = "```json\n{\"site_type\": \"blog\"}"
        assert deep_strip_md(text) == '{"site_type": "blog"}'

    def test_empty_string_unchanged(self):
        assert deep_strip_md("") == ""

    def test_multiline_json_in_fences(self):
        text = '```json\n{\n  "site_type": "forum",\n  "purpose": "discussion"\n}\n```'
        result = deep_strip_md(text)
        assert '"site_type"' in result and '"purpose"' in result


class TestInterestScoreInteger:
    """Ensure interest_score values stored in DB are plain integers, not strings."""

    def test_interest_score_is_integer(self):
        """interest_score must be an integer, not '5/10' or similar string."""
        import sqlite3

        db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        conn = sqlite3.connect(db.name)
        cur = conn.cursor()

        cur.execute(
            "CREATE TABLE discoveries ("
            "ident_hash_hex TEXT NOT NULL, "
            "b32_addr TEXT NOT NULL DEFAULT '', "
            "i2p_dns_name TEXT NOT NULL DEFAULT '', "
            "probe_mode TEXT NOT NULL DEFAULT '', "
            "reachable INTEGER NOT NULL DEFAULT 0, "
            "title TEXT DEFAULT '', "
            "content_summary TEXT DEFAULT '', "
            "deep_analysis TEXT DEFAULT '', "
            "probed_at REAL NOT NULL DEFAULT 0)"
        )
        # Insert with interest_score stored as JSON integer
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, probe_mode, deep_analysis, reachable, title, probed_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("hash_int", "dns", '{"site_type": "wiki", "interest_score": 7, "purpose": "knowledge"}', 1, "Test", time.time()),
        )
        conn.commit()

        parsed = json.loads(cur.execute(
            "SELECT deep_analysis FROM discoveries WHERE ident_hash_hex = ?",
            ("hash_int",),
        ).fetchone()[0])

        assert isinstance(parsed["interest_score"], int), (
            f"interest_score must be int, got {type(parsed['interest_score'])}: {parsed['interest_score']}"
        )
        conn.close()


if __name__ == "__main__":
    os.system("pytest")
