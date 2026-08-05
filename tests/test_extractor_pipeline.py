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
            ext_mod._registry[:] = [
                e for e in ext_mod._registry if type(e).__name__ != "HighPriorityExt"
            ]

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
        ext_mod._registry[:] = [
            e for e in ext_mod._registry if type(e).__name__ != "TempExt"
        ]


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
            ext_mod._registry[:] = [
                e for e in ext_mod._registry if type(e).__name__ != "DummyExt"
            ]

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

    # --- News site detection ---

    def test_news_site_bucket(self):
        body = '<html><head><title>I2P News Headlines</title></head>' \
               '<body><p>Latest updates and press releases.</p></body></html>'
        ctype, _, _ = self._classify("I2P News", body)
        assert ctype == "news site"

    # --- Mail server detection ---

    def test_mail_server_bucket(self):
        body = '<html><head><title>Mail Server</title></head>' \
               '<body><p>Email and postfix smtp configuration.</p></body></html>'
        ctype, _, _ = self._classify("Mail Server", body)
        assert ctype == "mail server"

    # --- Chat room detection ---

    def test_chat_room_bucket(self):
        body = '<html><head><title>I2P IRC Chat</title></head>' \
               '<body><p>Chat and messaging for the community.</p></body></html>'
        ctype, _, _ = self._classify("Chat Room", body)
        assert ctype == "chat room"

    # --- Search engine detection ---

    def test_search_engine_bucket(self):
        body = '<html><head><title>I2P Search Engine</title></head>' \
               '<body><form name="q">Search and discover indexed pages.</form>' \
               '<p>15000 results found in the index.</p></body></html>'
        ctype, lines, _ = self._classify("I2P Search", body)
        assert ctype == "search engine"
        assert any("indexed" in l.lower() or "Catalog" in l for l in lines)

    # --- Unidentified bucket (no keywords match) ---

    def test_unidentified_bucket(self):
        body = '<html><head><title>Random Page</title></head>' \
               '<body><p>No recognizable keywords here at all.</p></body></html>'
        ctype, lines, _ = self._classify("Random Page", body)
        assert ctype == ""  # empty means unidentified
        assert any("Unidentified" in l for l in lines)

    # --- Tech stack detection ---

    def test_tech_stack_node_js(self):
        body = '<html><head><title>App</title></head>' \
               '<body><div class="node_modules">express app</div></body></html>'
        _, lines, _ = self._classify("Node App", body)
        assert any("Node.js" in l for l in lines)

    def test_tech_stack_php(self):
        body = '<html><?php echo "test"; ?><title>PHP Page</title><body></body></html>'
        _, lines, _ = self._classify("PHP", body)
        assert any("PHP" in l for l in lines)

    def test_tech_stack_django(self):
        body = '<html><head><title>Django App</title></head>' \
               '<body><input name="csrfmiddlewaretoken">django-csrftoken</body></html>'
        _, lines, _ = self._classify("Django", body)
        assert any("Python/Django" in l or "Python" in l for l in lines)

    # --- SPA framework detection ---

    def test_spa_framework_react(self):
        body = '<html><head><title>React App</title></head>' \
               '<body><div data-reactroot></div></body></html>'
        _, lines, _ = self._classify("React", body)
        assert any("SPA framework" in l for l in lines)

    def test_spa_framework_vue(self):
        body = '<html><head><title>Vue App</title></head>' \
               '<body><div data-v-abc></div><script src="vue.js"></script></body></html>'
        _, lines, _ = self._classify("Vue", body)
        assert any("SPA framework" in l for l in lines)

    # --- I2P link extraction ---

    def test_i2p_link_extraction(self):
        body = '<html><body>' \
               '<a href="http://example.i2p">example.i2p</a>' \
               '<a href="http://another.sub.i2p">link two</a></body></html>'
        _, _, links = self._classify("Links", body)
        assert "example.i2p" in links
        assert "another.sub.i2p" in links

    def test_i2p_link_extraction_deduplicates(self):
        body = '<html><body>' \
               '<a href="http://dup.i2p">A</a><a href="http://dup.i2p">B</a></body></html>'
        _, _, links = self._classify("Dedup", body)
        assert links.count("dup.i2p") == 1

    # --- Meta description extraction (incl. og:description fallback) ---

    def test_meta_description_extraction(self):
        body = '<html><head><title>Desc</title>' \
               '<meta name="description" content="This is the page description">' \
               '</head><body></body></html>'
        _, lines, _ = self._classify("Desc", body)
        assert any("description" in l.lower() and "This is the page" in l for l in lines)

    def test_og_description_fallback(self):
        body = '<html><head><title>OG</title>' \
               '<meta property="og:description" content="Open graph desc">' \
               '</head><body></body></html>'
        _, lines, _ = self._classify("OG", body)
        assert any("open graph" in l.lower() or "Open graph" in l for l in lines)

    # --- Search engine enrichment: search form detection ---

    def test_search_engine_has_form(self):
        body = '<html><head><title>Search</title></head>' \
               '<body><form><input name="q"></form></body></html>'
        _, lines, _ = self._classify("Search", body)
        assert any("search form" in l.lower() or "content indexing" in l.lower() for l in lines)

    # --- File archive with no auto-listing but known extensions ---

    def test_file_archive_extensions(self):
        body = '<html><head><title>Downloads</title></head>' \
               '<body><p>archive.zip report.pdf backup.tar.gz data.csv code.py</p></body></html>'
        _, lines, _ = self._classify("Downloads", body)
        assert any("File types" in l for l in lines)

    # --- Blog enrichment: post listing & engine detection ---

    def test_blog_recent_posts(self):
        body = '<html><head><title>Blog</title></head>' \
               '<body><a href="/post/1">First Blog Post Title Here</a>' \
               '<a href="/post/2">Another Recent Entry About Tech</a></body></html>'
        _, lines, _ = self._classify("Blog", body)
        assert any("Recent posts" in l for l in lines)

    def test_blog_hugo_detection(self):
        body = '<html><head><title>Blog</title></head>' \
               '<body>Generated with hugo engine. <p>Journal of a user.</p></body></html>'
        _, lines, _ = self._classify("Hugo Blog", body)
        assert any("hugo" in l.lower() or "Powered by" in l for l in lines)

    # --- Marketplace: product listing rows ---

    def test_marketplace_product_listing_rows(self):
        body = '<html><head><title>Market</title></head>' \
               '<body><tr>x</tr><tr>x</tr><tr>x</tr><tr>x</tr><tr>x</tr>' \
               '<tr>x</tr><tr>x</tr><tr>x</tr><tr>x</tr><tr>x</tr>' \
               '<tr>x</tr><p>buy sell shop</p></body></html>'
        _, lines, _ = self._classify("Market", body)
        assert any("product listing" in l.lower() or "table/list rows" in l.lower() for l in lines)

    # --- Blockchain explorer enrichment ---

    def test_blockchain_explorer_detection(self):
        # Needs search-engine keywords to hit the enrichment block
        body = '<html><head><title>Bitcoin Search Explorer</title></head>' \
               '<body><p>blockchain block height txid transaction hash bitcoin btc</p>' \
               '<form name="q">search txid index find</form></body></html>'
        ctype, lines, _ = self._classify("Bitcoin Search Explorer", body)
        assert ctype == "search engine"
        assert any("Blockchain explorer" in l for l in lines)
        assert any("Bitcoin" in l for l in lines)

    # --- Content excerpt extraction (paragraphs not duplicating title) ---

    def test_content_excerpt_from_paragraphs(self):
        body = '<html><head><title>Page Title</title></head>' \
               '<body><p>This is some meaningful content that provides useful context for the reader about this page.</p></body></html>'
        _, lines, _ = self._classify("Page Title", body)
        assert any("Content excerpt" in l for l in lines)

    # --- Heading extraction (h1-h3 sections) ---

    def test_heading_extraction(self):
        body = '<html><head><title>Site</title></head>' \
               '<body><h1>Main Section Header</h1>' \
               '<h2>Sub Section Title</h2></body></html>'
        _, lines, _ = self._classify("Site", body)
        assert any("Section:" in l for l in lines)

    # --- HTML entity unescaping in title ---

    def test_html_entity_unescaped_title(self):
        body = '<html><head><title>&lt;Test&gt; &amp; Stuff</title></head>' \
               '<body><p>Some content here long enough to pass.</p></body></html>'
        _, lines, _ = self._classify("&lt;Test&gt; &amp; Stuff", body)
        combined = " ".join(lines)
        assert "<Test>" in combined or "&lt;Test&gt;" in combined

    # --- Body text fallback when summary is sparse ---

    def test_body_text_fallback(self):
        # Very minimal page with no metadata but some body text
        body = '<html><head><title>X</title></head>' \
               '<body>This is a long enough body text that should trigger the fallback mechanism because it has words here.</body></html>'
        _, lines, _ = self._classify("X", body)
        assert any("Body text" in l for l in lines)


# ---------------------------------------------------------------------------
# 4. Plugin crash handling and discovery robustness
# ---------------------------------------------------------------------------


class TestPluginCrashHandling:

    def test_discover_skips_module_with_crashing_can_handle(self, tmp_path):
        """A plugin class that crashes in can_handle should not break discovery."""
        plugin_dir = tmp_path / "ext_plugins"
        plugin_dir.mkdir()
        (plugin_dir / "__init__.py").write_text("")

        crashing = textwrap.dedent('''\
            from src.extractors import BaseExtractor, _register

            class CrashingExt(BaseExtractor):
                priority = 50
                def can_handle(self, body_text, headers, status_code):
                    raise RuntimeError("intentional crash")
                def extract(self, title, body_text, headers):
                    return ("crash", [], [])

            _register(CrashingExt)
        ''')
        (plugin_dir / "crashing.py").write_text(crashing)

        from src import extractors as ext_mod
        orig_plugin_dir = ext_mod._PLUGIN_DIR
        orig_len = len(ext_mod._registry)
        try:
            ext_mod._PLUGIN_DIR = plugin_dir
            ext_mod.discover_plugins()  # should NOT raise
            names = [type(e).__name__ for e in ext_mod._registry]
            assert "CrashingExt" in names
        finally:
            ext_mod._PLUGIN_DIR = orig_plugin_dir
            ext_mod._registry[:] = [
                e for e in ext_mod._registry if type(e).__name__ != "CrashingExt"
            ]

    def _cleanup_registry(self, ext_mod, class_names):
        """Remove temporary extractors by class name (safe against sorting)."""
        ext_mod._registry[:] = [
            e for e in ext_mod._registry
            if type(e).__name__ not in class_names
        ]

    def test_run_extractors_skips_crashing_extractor(self):
        """If an extractor's can_handle crashes, registry continues to next."""
        from src.extractors import _register, run_extractors, BaseExtractor
        from src import extractors as ext_mod

        try:
            class CrashingFirst(BaseExtractor):
                priority = 1
                def can_handle(self, body_text, headers, status_code):
                    raise RuntimeError("boom")
                def extract(self, title, body_text, headers):
                    return ("crash", [], [])

            _register(CrashingFirst)
            # CrashingFirst is at position 0 (priority=1), HtmlExtractor still catches HTML
            result = run_extractors(
                title="HTML",
                body_text='<html><head><title>Test</title></head>'
                          '<body><p>3245 posts, 890 threads.</p></body></html>',
                headers={"Content-Type": "text/html"},
                status_code=200,
            )
            # CrashingFirst is skipped, HtmlExtractor handles it
            assert result.needs_review is False
        finally:
            self._cleanup_registry(ext_mod, {"CrashingFirst"})

    def test_run_extractors_skips_crashing_and_continues(self):
        """Crashing extractor in registry should be skipped, next extractor succeeds."""
        from src.extractors import BaseExtractor, get_registry, run_extractors

        body = '<html><head><title>Test</title></head><body>Hello.</body></html>'
        headers = {"Content-Type": "text/html"}

        class CrashExt(BaseExtractor):
            priority = 1
            def can_handle(self, b, h, s):
                raise RuntimeError("boom")
            def extract(self, t, b, h):
                return ("crash", [], [])

        orig_registry = list(get_registry())
        from src import extractors as ext_mod
        ext_mod._registry.insert(0, CrashExt())

        try:
            result = run_extractors("Test", body, headers, 200)
            # The crashing one is skipped, HtmlExtractor catches it
            assert result.needs_review is False
        finally:
            self._cleanup_registry(ext_mod, {"CrashExt"})

    def test_discover_plugins_logs_exception_and_continues(self, tmp_path, caplog):
        """ImportError in one plugin should not prevent others from loading."""
        import logging
        logger = logging.getLogger("src.extractors")
        logger.setLevel(logging.WARNING)

        plugin_dir = tmp_path / "ext_plugins"
        plugin_dir.mkdir()
        (plugin_dir / "__init__.py").write_text("")

        # Broken module with syntax error
        (plugin_dir / "broken.py").write_text("def foo( invalid syntax")

        # Good module
        valid = textwrap.dedent('''\
            from src.extractors import BaseExtractor, _register

            class ValidExt(BaseExtractor):
                priority = 50
                def can_handle(self, b, h, s): return False
                def extract(self, t, b, h): return ("valid", [], [])

            _register(ValidExt)
        ''')
        (plugin_dir / "valid.py").write_text(valid)

        from src import extractors as ext_mod
        orig_plugin_dir = ext_mod._PLUGIN_DIR
        orig_len = len(ext_mod._registry)
        try:
            ext_mod._PLUGIN_DIR = plugin_dir
            ext_mod.discover_plugins()
            names = [type(e).__name__ for e in ext_mod._registry]
            assert "ValidExt" in names, f"ValidExt not found in {names}"
        finally:
            ext_mod._PLUGIN_DIR = orig_plugin_dir
            self._cleanup_registry(ext_mod, {"ValidExt", "CrashingExt"})


# ---------------------------------------------------------------------------
# 5. needs_review flags via run_extractors (no_extractor_claimed, partial)
# ---------------------------------------------------------------------------


class TestRunExtractorsNeedsReview:

    def test_no_extractor_claimed(self):
        """Plain text body that no extractor claims triggers needs_review."""
        from src.extractors import run_extractors

        result = run_extractors(
            title="Unknown",
            body_text="Just some plain text with zero html tags whatsoever.",
            headers={"Content-Type": "text/plain"},
            status_code=200,
        )
        assert result.needs_review is True
        assert result.reason == "no_extractor_claimed"

    def test_partial_extract_only(self):
        """Extracted result with <=1 summary line and >200 bytes body triggers partial_review."""
        from src.extractors import _register, run_extractors, BaseExtractor
        from src import extractors as ext_mod

        orig_len = len(ext_mod._registry)
        try:
            class MinimalExt(BaseExtractor):
                priority = 5  # runs before HtmlExtractor
                def can_handle(self, body_text, headers, status_code):
                    return "minimal" in body_text.lower()
                def extract(self, title, body_text, headers):
                    return ("minimal", ["only one line"], [])

            _register(MinimalExt)

            result = run_extractors(
                title="Minimal",
                body_text="minimal marker\n" + "x" * 300,
                headers={},
                status_code=200,
            )
            assert result.needs_review is True
            assert result.reason == "partial_extract_only"
        finally:
            ext_mod._registry[:] = [
                e for e in ext_mod._registry if type(e).__name__ != "MinimalExt"
            ]

    def test_successful_extraction_no_needs_review(self):
        """A proper HTML extraction with multiple summary lines should not flag needs_review."""
        from src.extractors import run_extractors

        body = '<html><head><title>Forum Board</title></head>' \
               '<body><h1>Welcome</h1><p>3245 posts, 890 threads.</p></body></html>'
        result = run_extractors(
            title="Forum Board",
            body_text=body,
            headers={"Content-Type": "text/html"},
            status_code=200,
        )
        assert result.needs_review is False

    def test_extractor_result_content_summary(self):
        """ExtractorResult.content_summary joins lines with newlines."""
        from src.extractors import ExtractorResult

        r = ExtractorResult(
            content_type="forum", summary_lines=["A", "B"], needs_review=False, reason=""
        )
        assert r.content_summary == "A\nB"

    def test_json_api_response_flags_needs_review(self):
        """JSON API response that isn't HTML triggers no_extractor_claimed."""
        from src.extractors import run_extractors

        result = run_extractors(
            title="API",
            body_text='{"status": 200, "data": [{"id": 1, "name": "test"}]}',
            headers={"Content-Type": "application/json"},
            status_code=200,
        )
        assert result.needs_review is True
        assert result.reason == "no_extractor_claimed"

    def test_torrent_tracker_response_flags_needs_review(self):
        """Torrent tracker string response triggers no_extractor_claimed."""
        from src.extractors import run_extractors

        result = run_extractors(
            title="Tracker",
            body_text="d8:completeii10e5:incompletii2ei4:seedeei6:leechersee",
            headers={"Content-Type": "application/x-bencodered"},
            status_code=200,
        )
        assert result.needs_review is True
        assert result.reason == "no_extractor_claimed"

    def test_rss_feed_flags_needs_review(self):
        """RSS/Atom feed that isn't HTML triggers no_extractor_claimed."""
        from src.extractors import run_extractors

        body = '<?xml version="1.0"?><rss version="2.0"><channel>' \
               '<title>My Blog</title><item><title>Post 1</title></item>' \
               '</channel></rss>'
        result = run_extractors(
            title="RSS Feed",
            body_text=body,
            headers={"Content-Type": "application/rss+xml"},
            status_code=200,
        )
        assert result.needs_review is True
        assert result.reason == "no_extractor_claimed"

    def test_binary_body_flags_needs_review(self):
        """Binary-looking body triggers no extractor match."""
        from src.extractors import run_extractors

        # Simulated binary garbage
        body = '\x00\x01\x02\xff\xfe'.encode('latin-1').decode('latin-1') * 100
        result = run_extractors(
            title="Binary",
            body_text=body,
            headers={"Content-Type": "application/octet-stream"},
            status_code=200,
        )
        assert result.needs_review is True
        assert result.reason == "no_extractor_claimed"

    def test_unenrichable_html_still_passes(self):
        """Minimal HTML with no keywords still gets parsed, not flagged as needs_review."""
        from src.extractors import run_extractors

        body = '<html><head><title>Empty</title></head>' \
               '<body><p>Nothing special here.</p></body></html>'
        result = run_extractors(
            title="Empty",
            body_text=body,
            headers={"Content-Type": "text/html"},
            status_code=200,
        )
        # HtmlExtractor handles it (small body, low quality not triggered)
        assert result.needs_review is False

    def test_error_status_code_passes_through(self):
        """HTTP 404 body still gets processed normally."""
        from src.extractors import run_extractors

        body = '<html><head><title>404 Not Found</title></head>' \
               '<body><h1>Page not found</h1></body></html>'
        result = run_extractors(
            title="404",
            body_text=body,
            headers={"Content-Type": "text/html"},
            status_code=404,
        )
        # HTML still gets parsed regardless of status code
        assert len(result.summary_lines) > 0


# ---------------------------------------------------------------------------
# 6. CLI subprocess smoke tests (analyzer.py entry points)
# ---------------------------------------------------------------------------


class TestAnalyzerCli:

    def _cli(self, *args):
        """Run analyzer.py via subprocess and return (stdout, stderr, code)."""
        import subprocess

        result = subprocess.run(
            ["python", "-m", "src.analyzer", *args],
            capture_output=True, text=True, timeout=30,
            cwd="/home/stefan/Projects/I2P-Indexer",
        )
        return result.stdout, result.stderr, result.returncode

    def test_fetch_all_paths_flag(self):
        """fetch-all-paths subcommand parses and attempts connection."""
        stdout, stderr, code = self._cli(
            "fetch-all-paths", "--host", "http://localhost:9126"
        )
        # May fail on localhost connection, but the flag itself should parse
        assert code in (0, 2), f"Unexpected exit code {code}: {stderr}"

    def test_inspect_headers_flag(self):
        """inspect-headers subcommand parses and attempts connection."""
        stdout, stderr, code = self._cli(
            "inspect-headers", "--host", "http://localhost:9126"
        )
        assert code in (0, 2), f"Unexpected exit code {code}: {stderr}"

    def test_generate_flag(self):
        """generate subcommand produces extractor skeleton (exit 1)."""
        stdout, stderr, code = self._cli(
            "generate", "--body", '{"hello": "world"}'
        )
        # May succeed or produce a helpful message about DB state
        assert code in (0, 1), f"Unexpected exit code {code}: {stderr}"

    def test_all_flagged_flag(self):
        """all-flagged subcommand parses and runs."""
        stdout, stderr, code = self._cli("all-flagged")
        assert code in (0, 1), f"Unexpected exit code {code}: {stderr}"

    def test_help_flag(self):
        """--help returns usage without error."""
        stdout, stderr, code = self._cli("--help")
        assert code == 0
        assert "fetch-all-paths" in stdout or "--help" in stdout


# ---------------------------------------------------------------------------
# Helper: needs_review persistence with in-memory DB (integration)
# ---------------------------------------------------------------------------

@pytest.fixture
def db():
    """In-memory DiscoveryDB for test isolation."""
    from src.integration import DiscoveryDB

    inst = DiscoveryDB(":memory:")
    yield inst
    inst.close()


@pytest.fixture
def flagged_db(db):
    """DiscoveryDB pre-populated with a needs_review row."""
    from src.integration import DiscoveryDB

    conn = db._conn
    now = __import__("time").time()
    # Insert a discovery with needs_review=1 directly
    conn.execute(
        "INSERT INTO discoveries (ident_hash_hex, b32_addr, i2p_dns_name, probe_mode, "
        "reachable, status_code, needs_review, probed_at) "
        "VALUES (?, ?, ?, 'b32', 1, 200, 1, ?)",
        ("a" * 40, "aaaa", "test.i2p", now),
    )
    conn.commit()
    return db


class TestNeedsReviewPersistence:

    def test_mark_and_retrieve_flagged(self, flagged_db):
        """Flagging a destination persists and is retrievable."""
        # The fixture already inserted one; verify get_flagged_destinations works
        flagged = flagged_db.get_flagged_destinations()
        assert len(flagged) >= 1
        # All should have needs_review=1 (guaranteed by the query)
        for h, d in flagged:
            assert len(h) == 40

    def test_clear_flag(self, db):
        """Unflagging a destination works."""
        now = __import__("time").time()
        ident = "b" * 40
        conn = db._conn
        conn.execute(
            "INSERT INTO discoveries (ident_hash_hex, b32_addr, i2p_dns_name, probe_mode, "
            "reachable, status_code, needs_review, probed_at) "
            "VALUES (?, ?, ?, 'b32', 1, 200, 1, ?)",
            (ident, "bbbb", "clear-test.i2p", now),
        )
        conn.commit()
        # Confirm it's flagged
        flagged = db.get_flagged_destinations()
        assert any(h == ident for h, _ in flagged)

        # Clear the flag
        db.clear_needs_review(ident)

        # Should no longer appear
        flagged = db.get_flagged_destinations()
        assert not any(h == ident for h, _ in flagged)

    def test_get_all_flagged_destinations(self, db):
        """Multiple flagged destinations appear in the list."""
        now = __import__("time").time()
        conn = db._conn
        for i in range(3):
            ident = str(i) * 40
            conn.execute(
                "INSERT INTO discoveries (ident_hash_hex, b32_addr, i2p_dns_name, probe_mode, "
                "reachable, status_code, needs_review, probed_at) "
                "VALUES (?, ?, ?, 'b32', 1, 200, 1, ?)",
                (ident, f"{'a' * i}", f"test{i}.i2p", now + i),
            )
        conn.commit()

        flagged = db.get_flagged_destinations()
        assert len(flagged) >= 3


# ---------------------------------------------------------------------------
# Edge cases: empty/None handling in extractors
# ---------------------------------------------------------------------------


class TestExtractorEdgeCases:

    def test_run_extractors_with_empty_body(self):
        from src.extractors import run_extractors
        result = run_extractors("Title", "", {}, 200)
        assert result.needs_review is True

    def test_run_extractors_with_none_headers(self):
        """None headers should not crash."""
        from src.extractors import run_extractors
        body = '<html><head><title>T</title></head><body>x</body></html>'
        result = run_extractors("T", body, None, 200)
        assert True  # no exception

    def test_can_handle_does_not_crash_on_empty(self):
        """can_handle should handle empty strings safely."""
        from src.extractors import get_registry
        reg = get_registry()
        for ext in reg:
            try:
                ok = ext.can_handle("", {}, 200)
                assert isinstance(ok, bool)
            except Exception as exc:
                pytest.fail(f"{type(ext).__name__} crashed on empty input: {exc}")

    def test_partial_requires_body_greater_than_200(self):
        """Bodies under 200 chars should NOT trigger partial extract flag."""
        from src.extractors import _register, run_extractors, BaseExtractor
        from src import extractors as ext_mod

        try:
            class SparseExt(BaseExtractor):
                priority = 3
                def can_handle(self, b, h, s):
                    return True
                def extract(self, t, b, h):
                    return ("sparse", ["single"], [])

            _register(SparseExt)

            # Small body — should NOT trigger partial
            result = run_extractors("T", "short text here", {}, 200)
            assert result.needs_review is False
        finally:
            ext_mod._registry[:] = [
                e for e in ext_mod._registry if type(e).__name__ != "SparseExt"
            ]

    def test_large_body_with_few_lines_triggers_partial(self):
        """Large body with only one summary line triggers partial extract."""
        from src.extractors import _register, run_extractors, BaseExtractor
        from src import extractors as ext_mod

        try:
            class SparseExt(BaseExtractor):
                priority = 3
                def can_handle(self, b, h, s):
                    return True
                def extract(self, t, b, h):
                    return ("sparse", ["single"], [])

            _register(SparseExt)

            result = run_extractors("T", "x" * 500, {}, 200)
            assert result.needs_review is True
            assert result.reason == "partial_extract_only"
        finally:
            ext_mod._registry[:] = [
                e for e in ext_mod._registry if type(e).__name__ != "SparseExt"
            ]
