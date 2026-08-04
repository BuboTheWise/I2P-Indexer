"""Tests for the modular extractor pipeline, analyzer CLI, and HtmlExtractor.

Covers:
  1. Extractor registry lifecycle (register, priority sort, get_registry)
  2. Plugin discovery via ext_plugins/ (mocked filesystem + importlib)
  3. HtmlExtractor migration: can_handle() detection and bucket classification
  4. needs_review flags: no_extractor_claimed, partial_extract_only, DB roundtrip
  5. Analyzer CLI: --generate syntax validation, subprocess smoke tests
  6. Non-HTML body fixtures: JSON API response, torrent metadata, RSS/Atom feed
     to confirm run_extractors yields empty result + needs_review=True
"""
from __future__ import annotations

import inspect
import pathlib
import sys
import tempfile
import textwrap
from importlib import reload as reload_module
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# 1. Extractor registry lifecycle
# ---------------------------------------------------------------------------


class TestExtractorRegistry:
    """Registration, priority sorting, and get_registry() behavior."""

    def test_default_registry_contains_html(self):
        """HtmlExtractor is auto-registered by plugin discovery on import."""
        from src.extractors import get_registry

        registry = get_registry()
        names = [type(e).__name__ for e in registry]
        assert "HtmlExtractor" in names, (
            f"HtmlExtractor not auto-discovered. Registry has: {names}"
        )

    def test_registry_sorted_by_priority(self):
        """Extractors with lower priority=int appear first."""
        from src.extractors import _register, get_registry, _registry

        class LowPriorityExtractor:
            pass  # dummy

        # Temporarily register a very-high-priority extractor (priority=10)
        from importlib.machinery import ModuleSpec
        from src import extractors as ext_mod

        orig_len = len(ext_mod._registry)

        try:
            class HighPriorityExt(ext_mod.BaseExtractor):
                priority = 10

                def can_handle(self, body_txt, hdrs, sc):
                    return False

                def extract(self, title, body_txt, hdrs):
                    return ("", [], [])

            _register(HighPriorityExt)
            registry = get_registry()
            # HtmlExtractor has priority=90; HighPriorityExt is 10
            priorities = [e.priority for e in registry]
            # Should be sorted ascending
            assert priorities == sorted(priorities), (
                f"Registry not sorted by priority: {priorities}"
            )
        finally:
            # Restore registry to original length
            while len(ext_mod._registry) > orig_len:
                ext_mod._registry.pop()

    def test_get_registry_returns_copy(self):
        """Modifying the returned list does not affect internal state."""
        from src.extractors import _register, get_registry
        from src import extractors as ext_mod

        orig = list(ext_mod._registry)
        snapshot = get_registry()
        snapshot.clear()
        # Internal registry untouched
        assert ext_mod._registry is not snapshot
        # Restore
        ext_mod._registry[:] = orig

    def test_register_decorator_returns_class(self):
        """_register(cls) returns cls unchanged so @use works."""
        from src.extractors import _register, BaseExtractor
        from src import extractors as ext_mod

        orig_len = len(ext_mod._registry)

        class TempExt(BaseExtractor):
            priority = 5
            def can_handle(self, b, h, s): return False
            def extract(self, t, b, h): return ("", [], [])

        result = _register(TempExt)
        assert result is TempExt
        # Clean up
        while len(ext_mod._registry) > orig_len:
            ext_mod._registry.pop()


# ---------------------------------------------------------------------------
# 2. Plugin discovery (mocked filesystem + importlib)
# ---------------------------------------------------------------------------


class TestPluginDiscovery:

    def test_discover_plugins_ignores_init_files(self, tmp_path):
        """__init__.py and private modules like _helper.py are skipped."""
        plugin_dir = tmp_path / "ext_plugins"
        plugin_dir.mkdir()

        # Write a dummy __init__.py (should be ignored)
        (plugin_dir / "__init__.py").write_text("")
        # Write a private module (should be ignored)
        (plugin_dir / "_private.py").write_text("# nothing here")
        # Write a valid plugin that registers itself
        valid = textwrap.dedent('''\
            from src.extractors import BaseExtractor, _register

            class DummyExt(BaseExtractor):
                priority = 50
                def can_handle(self, body_text, headers, status_code):
                    return False
                def extract(self, title, body_text, headers):
                    return ("dummy", ["line"], [])

            _register(DummyExt)
        ''')
        (plugin_dir / "dummy.py").write_text(valid)

        from src.extractors import _PLUGIN_DIR, discover_plugins, _registry
        from src import extractors as ext_mod

        orig_plugin_dir = ext_mod._PLUGIN_DIR
        orig_len = len(ext_mod._registry)
        try:
            ext_mod._PLUGIN_DIR = plugin_dir
            discover_plugins()
            # DummyExt should have been registered
            names = [type(e).__name__ for e in ext_mod._registry]
            assert "DummyExt" in names, f"Not found in {names}"
        finally:
            ext_mod._PLUGIN_DIR = orig_plugin_dir
            # Clean up registry entries added by discovery
            while len(ext_mod._registry) > orig_len:
                ext_mod._registry.pop()

    def test_discover_plugins_skips_missing_directory(self):
        """No error when ext_plugins/ simply does not exist."""
        from src.extractors import discover_plugins, _PLUGIN_DIR
        from src import extractors as ext_mod

        # Point to nonexistent dir
        orig = ext_mod._PLUGIN_DIR
        try:
            ext_mod._PLUGIN_DIR = pathlib.Path("/nonexistent/path")
            discover_plugins()  # should not raise
        finally:
            ext_mod._PLUGIN_DIR = orig


# ---------------------------------------------------------------------------
# 3. HtmlExtractor — can_handle() detection and classification buckets
# ---------------------------------------------------------------------------


class TestHtmlExtractorCanHandle:

    def _make_extractor(self):
        from src.ext_plugins.html_extractor import HtmlExtractor
        return HtmlExtractor()

    def test_detects_html_content_type_header(self):
        ext = self._make_extractor()
        assert ext.can_handle(
            "some body text",
            {"Content-Type": "text/html; charset=utf-8"},
            200,
        )

    def test_detects_doctype_in_body(self):
        body = '<!DOCTYPE html>\n<html><head><title>X</title></head>'
        ext = self._make_extractor()
        assert ext.can_handle(body, {}, 200)

    def test_detects_html_tag_in_body(self):
        body = '<html><body>content</body></html>'
        ext = self._make_extractor()
        assert ext.can_handle(body, {}, 200)

    def test_detects_meta_tag_start(self):
        body = '<meta charset="utf-8"><title>X</title>'
        ext = self._make_extractor()
        assert ext.can_handle(body, {}, 200)

    def test_detects_body_with_enough_tags(self):
        # Fallback: >=3 tags + body length >50
        body = '<div><span><a>Some rather longer text to satisfy the check.</a>'
        ext = self._make_extractor()
        assert ext.can_handle(body, {}, 200)

    def test_rejects_short_body_with_few_tags(self):
        # Only 1 tag and short body — should NOT be handled
        body = '<div>short</div>'
        ext = self._make_extractor()
        assert not ext.can_handle(body, {"Content-Type": "application/octet"}, 200)

    def test_rejects_plain_text(self):
        body = "Just regular text with no tags at all whatsoever here."
        ext = self._make_extractor()
        headers = {"Content-Type": "text/plain"}
        assert not ext.can_handle(body, headers, 200)


class TestHtmlExtractorClassification:
    """Bucket detection for all nine content type categories."""

    def _classify(self, title: str, body: str):
        from src.ext_plugins.html_extractor import _do_classify
        return _do_classify(title, body)

    # --- Forum detection ---

    def test_forum_bucket_and_stats(self):
        body = textwrap.dedent('''\
            <html>
            <head><title>I2P Forum Board</title>
            <meta name="description" content="Community discussion board">
            </head>
            <body>
            <h1>Welcome to the Forum</h1>
            <p>3245 posts, 890 threads, 120 members active.</p>
            <a href="/topic/what-is-i2p">What is I2P?</a>
            <a href="/topic/setup-guide">Setup guide for new users</a>
            </body></html>''')
        ctype, lines, links = self._classify("I2P Forum Board", body)
        assert ctype == "forum"
        # Check preamble exists
        assert any("Forum" in l for l in lines)
        # Stats line present
        assert any("Stats:" in l for l in lines)

    def test_forum_software_detection(self):
        body = textwrap.dedent('''\
            <html><head><title>Board</title></head>
            <body>Powered by phpBB 3.3
            <p>100 posts, 50 threads</p></body></html>''')
        ctype, lines, _ = self._classify("Board", body)
        assert ctype == "forum"
        assert any("phpBB" in l for l in lines)

    # --- Wiki detection ---

    def test_wiki_bucket(self):
        body = '<html><head><title>I2P Wiki - Knowledge Base</title></head>' \
               '<body><p>This mediawiki hosts documentation.</p></body></html>'
        ctype, _, _ = self._classify("I2P Wiki", body)
        assert ctype == "wiki"

    # --- Blog detection ---

    def test_blog_bucket_with_rss(self):
        body = textwrap.dedent('''\
            <html><head><title>My I2P Blog</title></head>
            <body><h1>Latest Entries</h1>
            <p>Diary of an I2P user — journal entries below.</p>
            <a href="/atom.xml">Atom feed</a>
            <div class="wp-content">Post A</div>
            <a href="/post/first">First Post Title</a>
            <a href="/post/second">Second Entry About Privacy</a>
            </body></html>''')
        ctype, lines, _ = self._classify("My I2P Blog", body)
        assert ctype == "blog"
        assert any("WordPress" in l for l in lines)
        assert any("RSS/Atom" in l or "feed" in l.lower() for l in lines)

    # --- File archive detection ---

    def test_file_archive_with_directory_listing(self):
        body = textwrap.dedent('''\
            <html><head><title>File Archive Mirror</title></head>
            <body><h1>Index of /</h1>
            <p>Parent directory listing — download repository.</p>
            <a href="docs.zip">docs.zip</a>
            <a href="report.pdf">report.pdf</a>
            <a href="backup.tar.gz">backup.tar.gz</a>
            </body></html>''')
        ctype, lines, _ = self._classify("File Archive", body)
        assert ctype == "file archive"
        assert any("Apache/Nginx" in l or "auto-generated" in l.lower() for l in lines) or \
               any("File types" in l for l in lines)

    # --- Marketplace detection ---

    def test_marketplace_with_categories_and_pricing(self):
        body = textwrap.dedent('''\
            <html><head><title>I2P Market Store</title></head>
            <body><h1>Welcome to the Shop</h1>
            <p>Buy and sell digital goods, software, hardware.</p>
            <tr><td>Item 1 - 0.5 BTC</td></tr>
            <tr><td>Item 2 - service plan</td></tr>
            <li>Vendor #42 listing</li>
            <li>Vendor #7 listing</li>
            </body></html>''')
        ctype, lines, _ = self._classify("Market Store", body)
        assert ctype == "marketplace"
        assert any("Categories" in l for l in lines)
        assert any("Pricing" in l or "pricing" in l.lower() for l in lines)
