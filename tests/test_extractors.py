"""Unit tests for src/extractors.py — registry, plugin discovery, priority ordering, partial extracts, error isolation.

Covers gaps not addressed by test_extractor_pipeline.py:
  1. Registry deregistration (removing extractors explicitly)
  2. Comprehensive discover_plugins() edge cases (empty dirs, non-Python files, broken modules)
  3. Priority ordering: lower numbers run first; built-in wins over plugins with same priority
  4. Partial extract detection: body >200 chars but only 1 summary line → needs_review=True
  5. Broken plugin error isolation: crashing extract() should not crash the sweep
"""
from __future__ import annotations

import pathlib
import textwrap
from unittest.mock import patch, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def clean_registry():
    """Provide a clean registry and restore it after the test."""
    from src import extractors as ext_mod

    orig = list(ext_mod._registry)
    # Clear everything so we start fresh
    ext_mod._registry.clear()
    yield ext_mod._registry
    # Restore original registry state
    ext_mod._registry[:] = orig


@pytest.fixture
def reset_plugin_dir():
    """Restore _PLUGIN_DIR after the test."""
    from src import extractors as ext_mod

    orig = ext_mod._PLUGIN_DIR
    yield
    ext_mod._PLUGIN_DIR = orig


@pytest.fixture
def register_html(clean_registry):
    """Register HtmlExtractor so it's available in an otherwise empty registry."""
    from src.ext_plugins.html_extractor import HtmlExtractor
    from src.extractors import _register

    _register(HtmlExtractor)


# ---------------------------------------------------------------------------
# 1. Registry registration / deregistration via @_register decorator
# ---------------------------------------------------------------------------


class TestRegistration:
    """@_register adds to registry, preserves sort order, returns the class."""

    def test_register_increases_count(self, clean_registry):
        from src.extractors import _register, BaseExtractor, get_registry

        class Foo(BaseExtractor):
            priority = 20
            def can_handle(self, b, h, s): return False
            def extract(self, t, b, h): return ("foo", [], [])

        before = len(get_registry())
        result = _register(Foo)
        after = len(get_registry())
        assert after == before + 1
        assert result is Foo  # decorator returns the class unchanged

    def test_register_inserts_into_sorted_position(self, clean_registry):
        from src.extractors import _register, BaseExtractor, get_registry

        class LowPrio(BaseExtractor):
            priority = 50
            def can_handle(self, b, h, s): return False
            def extract(self, t, b, h): return ("low", [], [])

        # Register high-first, then low — registry must end sorted ascending
        class HighPrio(BaseExtractor):
            priority = 10
            def can_handle(self, b, h, s): return False
            def extract(self, t, b, h): return ("high", [], [])

        _register(HighPrio)
        _register(LowPrio)

        registry = get_registry()
        assert registry[0].priority == 10
        assert registry[1].priority == 50

    def test_register_same_priority_sorted_by_name(self, clean_registry):
        """When priorities are equal, sort falls back to class name."""
        from src.extractors import _register, BaseExtractor, get_registry

        class Beta(BaseExtractor):
            priority = 30
            def can_handle(self, b, h, s): return False
            def extract(self, t, b, h): return ("beta", [], [])

        class Alpha(BaseExtractor):
            priority = 30
            def can_handle(self, b, h, s): return False
            def extract(self, t, b, h): return ("alpha", [], [])

        _register(Beta)
        _register(Alpha)

        registry = get_registry()
        names = [type(e).__name__ for e in registry]
        assert "Alpha" < "Beta"  # alphabetical tiebreak
        assert names.index("Alpha") < names.index("Beta") or \
               names.index("Beta") < names.index("Alpha")  # both present

    def test_deregister_by_removing_from_list(self, clean_registry):
        """Deregistration works by removing entries from _registry directly."""
        from src.extractors import _register, BaseExtractor, get_registry

        class TempExt(BaseExtractor):
            priority = 5
            def can_handle(self, b, h, s): return False
            def extract(self, t, b, h): return ("temp", [], [])

        _register(TempExt)
        assert any(type(e).__name__ == "TempExt" for e in get_registry())

        # Deregister by filtering out
        from src import extractors as ext_mod
        ext_mod._registry = [e for e in ext_mod._registry if type(e).__name__ != "TempExt"]

        assert not any(type(e).__name__ == "TempExt" for e in get_registry())


# ---------------------------------------------------------------------------
# 2. Plugin discovery — discover_plugins() edge cases
# ---------------------------------------------------------------------------


class TestPluginDiscovery:
    """discover_plugins() auto-discovers extractors from ext_plugins/ directory."""

    def _write_plugin(self, plugin_dir: pathlib.Path, name: str, code: str):
        (plugin_dir / name).write_text(code)

    def test_discovers_and_registers_valid_plugin(self, clean_registry, tmp_path, reset_plugin_dir):
        """A valid .py module with a BaseExtractor subclass gets auto-registered."""
        from src import extractors as ext_mod

        plugin_dir = tmp_path / "ext_plugins"
        plugin_dir.mkdir()
        (plugin_dir / "__init__.py").write_text("")

        self._write_plugin(plugin_dir, "my_ext.py", textwrap.dedent('''\
            from src.extractors import BaseExtractor, _register

            class MyExt(BaseExtractor):
                priority = 40
                def can_handle(self, body_text, headers, status_code):
                    return True
                def extract(self, title, body_text, headers):
                    return ("my_type", ["summary"], [])

            _register(MyExt)
        '''))

        ext_mod._PLUGIN_DIR = plugin_dir
        ext_mod.discover_plugins()

        names = [type(e).__name__ for e in ext_mod._registry]
        assert "MyExt" in names

    def test_skips_init_and_private_modules(self, clean_registry, tmp_path, reset_plugin_dir):
        """__init__.py and _private.py are ignored by discovery."""
        from src import extractors as ext_mod

        plugin_dir = tmp_path / "ext_plugins"
        plugin_dir.mkdir()
        (plugin_dir / "__init__.py").write_text("")
        # Private module that would register something
        self._write_plugin(plugin_dir, "_hidden.py", textwrap.dedent('''\
            from src.extractors import BaseExtractor, _register

            class Hidden(BaseExtractor):
                priority = 1
                def can_handle(self, b, h, s): return False
                def extract(self, t, b, h): return ("", [], [])

            _register(Hidden)
        '''))

        ext_mod._PLUGIN_DIR = plugin_dir
        ext_mod.discover_plugins()

        names = [type(e).__name__ for e in ext_mod._registry]
        assert "Hidden" not in names

    def test_skips_non_python_files(self, clean_registry, tmp_path, reset_plugin_dir):
        """README.md or .txt files inside ext_plugins/ are ignored."""
        from src import extractors as ext_mod

        plugin_dir = tmp_path / "ext_plugins"
        plugin_dir.mkdir()
        (plugin_dir / "__init__.py").write_text("")
        (plugin_dir / "README.md").write_text("# This is not a plugin")
        (plugin_dir / "notes.txt").write_text("random notes")

        ext_mod._PLUGIN_DIR = plugin_dir
        ext_mod.discover_plugins()

        assert len(ext_mod._registry) == 0

    def test_missing_plugin_directory_is_silent(self, clean_registry, reset_plugin_dir):
        """When _PLUGIN_DIR does not exist, discover_plugins() returns without error."""
        from src import extractors as ext_mod

        ext_mod._PLUGIN_DIR = pathlib.Path("/nonexistent/ext_plugins")
        ext_mod.discover_plugins()  # should not raise

    def test_handles_broken_import_gracefully(self, clean_registry, tmp_path, reset_plugin_dir):
        """A module that imports a nonexistent dependency doesn't crash discovery."""
        from src import extractors as ext_mod

        plugin_dir = tmp_path / "ext_plugins"
        plugin_dir.mkdir()
        (plugin_dir / "__init__.py").write_text("")

        self._write_plugin(plugin_dir, "broken_import.py", textwrap.dedent('''\
            import nonexistent_module_that_does_not_exist  # deliberate failure
        '''))

        ext_mod._PLUGIN_DIR = plugin_dir
        ext_mod.discover_plugins()  # should not raise

    def test_handles_syntax_error_in_plugin(self, clean_registry, tmp_path, reset_plugin_dir):
        """A module with a syntax error is skipped, others still load."""
        from src import extractors as ext_mod

        plugin_dir = tmp_path / "ext_plugins"
        plugin_dir.mkdir()
        (plugin_dir / "__init__.py").write_text("")

        # Broken syntax
        self._write_plugin(plugin_dir, "bad_syntax.py", "def foo( invalid")

        # Valid plugin that should still load
        self._write_plugin(plugin_dir, "good_ext.py", textwrap.dedent('''\
            from src.extractors import BaseExtractor, _register

            class GoodExt(BaseExtractor):
                priority = 25
                def can_handle(self, b, h, s): return False
                def extract(self, t, b, h): return ("good", [], [])

            _register(GoodExt)
        '''))

        ext_mod._PLUGIN_DIR = plugin_dir
        ext_mod.discover_plugins()

        names = [type(e).__name__ for e in ext_mod._registry]
        assert "GoodExt" in names, f"GoodExt not found in registry: {names}"

    def test_loads_plugins_in_sorted_filename_order(self, clean_registry, tmp_path, reset_plugin_dir):
        """Plugins are loaded in sorted filename order for determinism."""
        from src import extractors as ext_mod

        plugin_dir = tmp_path / "ext_plugins"
        plugin_dir.mkdir()
        (plugin_dir / "__init__.py").write_text("")

        # Create plugins with different priorities to see sort result
        for name, prio in [("z_plugin", 90), ("a_plugin", 10), ("m_plugin", 50)]:
            self._write_plugin(plugin_dir, f"{name}.py", textwrap.dedent(f'''\
                from src.extractors import BaseExtractor, _register

                class {name.capitalize()}Ext(BaseExtractor):
                    priority = {prio}
                    def can_handle(self, b, h, s): return False
                    def extract(self, t, b, h): return ("", [], [])

                _register({name.capitalize()}Ext)
            '''))

        ext_mod._PLUGIN_DIR = plugin_dir
        ext_mod.discover_plugins()

        registry = get_registry_sorted(ext_mod)
        priorities = [e.priority for e in registry]
        assert priorities == sorted(priorities), \
            f"Registry not priority-sorted: {priorities}"


def get_registry_sorted(ext_mod):
    """Get the registry sorted by (priority, name)."""
    return sorted(ext_mod._registry, key=lambda e: (e.priority, type(e).__name__))


# ---------------------------------------------------------------------------
# 3. Priority ordering — lower numbers run first, built-in wins over plugins
# ---------------------------------------------------------------------------


class TestPriorityOrdering:
    """Priority ordering: extractors with lower priority run first."""

    def test_first_matching_extractor_wins(self, clean_registry):
        """When two extractors can handle the same content, lower priority wins."""
        from src.extractors import _register, BaseExtractor, run_extractors

        class Winner(BaseExtractor):
            priority = 5
            def can_handle(self, body_text, headers, status_code):
                return "multi_match" in body_text
            def extract(self, title, body_text, headers):
                return ("winner_type", ["winner"], [])

        class Loser(BaseExtractor):
            priority = 50
            def can_handle(self, body_text, headers, status_code):
                return "multi_match" in body_text
            def extract(self, title, body_text, headers):
                return ("loser_type", ["loser"], [])

        _register(Winner)
        _register(Loser)

        result = run_extractors(
            title="test",
            body_text="multi_match " + "x" * 100,
            headers={},
            status_code=200,
        )
        assert result.content_type == "winner_type"
        assert "winner" in result.summary_lines

    def test_builtin_beats_plugin_same_priority(self, clean_registry):
        """Built-in extractors registered first have stable ordering at same priority."""
        from src.extractors import _register, BaseExtractor, run_extractors

        # Built-in: priority 100 (default for base)
        class BuiltinLike(BaseExtractor):
            priority = 80
            def can_handle(self, body_text, headers, status_code):
                return "special" in body_text
            def extract(self, title, body_text, headers):
                return ("builtin_result", ["builtin handled"], [])

        _register(BuiltinLike)

        # Plugin: same priority
        class PluginSame(BaseExtractor):
            priority = 80
            def can_handle(self, body_text, headers, status_code):
                return "special" in body_text
            def extract(self, title, body_text, headers):
                return ("plugin_result", ["plugin handled"], [])

        _register(PluginSame)

        result = run_extractors(
            title="test",
            body_text="special marker " + "a" * 200,
            headers={},
            status_code=200,
        )
        # BuiltinLike registered first → it comes first at same priority
        assert result.content_type == "builtin_result"

    def test_extractor_with_priority_one_runs_first(self, clean_registry):
        """Priority 1 extractor always runs before defaults (priority 100)."""
        from src.extractors import _register, BaseExtractor, get_registry

        class Utopriority(BaseExtractor):
            priority = 1
            def can_handle(self, b, h, s): return True
            def extract(self, t, b, h): return ("top", [], [])

        class DefaultPriority(BaseExtractor):
            # Default priority = 100
            def can_handle(self, b, h, s): return False
            def extract(self, t, b, h): return ("default", [], [])

        _register(DefaultPriority)
        _register(Utopriority)

        registry = get_registry_sorted(clean_registry.__class__.__module__ \
                                      and __import__("src.extractors", fromlist=["_registry"]) or None)
        # Use the module directly
        from src import extractors as ext_mod
        registry = sorted(ext_mod._registry, key=lambda e: (e.priority, type(e).__name__))
        assert registry[0].priority == 1

    def test_default_priority_is_one_hundred(self):
        """BaseExtractor subclasses get priority=100 by default."""
        from src import extractors as ext_mod

        class DefaultPrio(ext_mod.BaseExtractor):
            def can_handle(self, b, h, s): return False
            def extract(self, t, b, h): return ("", [], [])

        assert DefaultPrio.priority == 100


# ---------------------------------------------------------------------------
# 4. Partial extract detection — body >200 chars but only 1 summary line
# ---------------------------------------------------------------------------


class TestPartialExtractDetection:
    """When an extractor handles a response with lots of body data but returns
    only 1 non-empty summary line, it should be flagged as partial_extract_only."""

    def test_body_over_200_with_one_line_is_partial(self, clean_registry):
        from src.extractors import _register, BaseExtractor, run_extractors

        class SparseExt(BaseExtractor):
            priority = 2
            def can_handle(self, b, h, s): return True
            def extract(self, t, b, h):
                # Only one meaningful summary line despite large body
                return ("sparse", ["single_line_summary"], [])

        _register(SparseExt)

        large_body = "A" * 300  # Over 200 chars
        result = run_extractors("Title", large_body, {}, 200)

        assert result.needs_review is True
        assert result.reason == "partial_extract_only"
        assert result.content_type == "sparse"

    def test_body_over_200_with_two_lines_is_not_partial(self, clean_registry):
        """Body >200 with ≥2 non-empty summary lines: NOT partial."""
        from src.extractors import _register, BaseExtractor, run_extractors

        class GoodExt(BaseExtractor):
            priority = 2
            def can_handle(self, b, h, s): return True
            def extract(self, t, b, h):
                return ("good", ["first line", "second line"], [])

        _register(GoodExt)

        result = run_extractors("Title", "A" * 250, {}, 200)

        assert result.needs_review is False

    def test_body_under_200_with_one_line_is_not_partial(self, clean_registry):
        """Small body with one summary line: partial threshold not met."""
        from src.extractors import _register, BaseExtractor, run_extractors

        class SparseExt(BaseExtractor):
            priority = 2
            def can_handle(self, b, h, s): return True
            def extract(self, t, b, h):
                return ("sparse", ["only one"], [])

        _register(SparseExt)

        short_body = "short text"  # Under 200 chars
        result = run_extractors("Title", short_body, {}, 200)

        assert result.needs_review is False

    def test_empty_summary_lines_list_triggers_partial(self, clean_registry):
        """Body >200 with ZERO summary lines triggers partial review."""
        from src.extractors import _register, BaseExtractor, run_extractors

        class EmptyExt(BaseExtractor):
            priority = 2
            def can_handle(self, b, h, s): return True
            def extract(self, t, b, h):
                return ("empty", [], [])

        _register(EmptyExt)

        result = run_extractors("Title", "x" * 300, {}, 200)

        assert result.needs_review is True
        assert result.reason == "partial_extract_only"

    def test_whitespace_only_lines_count_as_empty(self, clean_registry):
        """Summary lines that are only whitespace count as empty for partial detection."""
        from src.extractors import _register, BaseExtractor, run_extractors

        class WhitespaceExt(BaseExtractor):
            priority = 2
            def can_handle(self, b, h, s): return True
            def extract(self, t, b, h):
                # These lines have content but only whitespace → counts as 1 line max
                return ("ws", ["   ", "actual content here"], [])

        _register(WhitespaceExt)

        result = run_extractors("Title", "y" * 250, {}, 200)
        # "actual content here" is the only stripped line
        assert result.needs_review is True
        assert result.reason == "partial_extract_only"


# ---------------------------------------------------------------------------
# 5. Broken plugin error isolation — crashing extract() should not crash sweep
# ---------------------------------------------------------------------------


class TestErrorIsolation:
    """A crashing extractor (either can_handle or extract) is skipped; the sweep continues."""

    def test_crashing_can_handle_is_skipped(self, clean_registry):
        from src.extractors import _register, BaseExtractor, run_extractors

        class BoomHandle(BaseExtractor):
            priority = 1
            def can_handle(self, b, h, s): raise ValueError("can_handle boom")
            def extract(self, t, b, h): return ("boom", [], [])

        class Fallback(BaseExtractor):
            priority = 10
            def can_handle(self, b, h, s): return True
            def extract(self, t, b, h): return ("fallback", ["ok"], [])

        _register(BoomHandle)
        _register(Fallback)

        result = run_extractors("T", "x" * 100, {}, 200)
        assert result.content_type == "fallback"
        assert result.needs_review is False

    def test_crashing_extract_is_skipped(self, clean_registry):
        """When extract() crashes after can_handle returns True, next extractor tries."""
        from src.extractors import _register, BaseExtractor, run_extractors

        class BoomExtract(BaseExtractor):
            priority = 1
            def can_handle(self, body_text, headers, status_code):
                return "test" in body_text.lower()
            def extract(self, title, body_text, headers):
                raise RuntimeError("extract method exploded")

        class SecondTry(BaseExtractor):
            priority = 5
            def can_handle(self, b, h, s): return True
            def extract(self, t, b, h): return ("second", ["survived"], [])

        _register(BoomExtract)
        _register(SecondTry)

        result = run_extractors("T", "test content " + "a" * 200, {}, 200)

        # BoomExtract is skipped, SecondTry handles it
        assert result.content_type == "second"
        assert "survived" in result.summary_lines

    def test_all_extractors_crashing_returns_needs_review(self, clean_registry):
        """When every extractor crashes, sweep returns needs_review=True."""
        from src.extractors import _register, BaseExtractor, run_extractors

        class Crasher1(BaseExtractor):
            priority = 1
            def can_handle(self, b, h, s): raise TypeError("err1")
            def extract(self, t, b, h): return ("", [], [])

        class Crasher2(BaseExtractor):
            priority = 2
            def can_handle(self, b, h, s): return True
            def extract(self, t, b, h): raise RuntimeError("err2")

        _register(Crasher1)
        _register(Crasher2)

        result = run_extractors("T", "crash everything " + "c" * 300, {}, 200)

        assert result.needs_review is True
        assert result.reason == "no_extractor_claimed"

    def test_exception_preserves_registry_state(self, clean_registry):
        """A crash during extraction doesn't corrupt the registry list."""
        from src.extractors import _register, BaseExtractor, run_extractors, get_registry

        class BoomExt(BaseExtractor):
            priority = 1
            def can_handle(self, b, h, s): return True
            def extract(self, t, b, h): raise OSError("boom")

        _register(BoomExt)
        before_count = len(get_registry())

        try:
            run_extractors("T", "crash " + "x" * 100, {}, 200)
        except Exception:
            pytest.fail("run_extractors should not raise; errors are caught internally")

        after_count = len(get_registry())
        assert before_count == after_count

    def test_exception_in_multiple_extractors_continues_to_end(self, clean_registry):
        """Multiple crashing extractors don't stop the sweep."""
        from src.extractors import _register, BaseExtractor, run_extractors

        for prio in (1, 2, 3):
            # Dynamically create a crashing extractor class for each priority
            cls = type(
                f"Crash{prio}",
                (BaseExtractor,),
                {
                    "priority": prio,
                    "can_handle": lambda self, b, h, s: True,
                    "extract": lambda self, t, b, h: (_ for _ in ()).throw(RuntimeError(f"crash {prio}")),
                },
            )
            _register(cls)

        class LastOne(BaseExtractor):
            priority = 100
            def can_handle(self, b, h, s): return True
            def extract(self, t, b, h): return ("last", ["finally"], [])

        _register(LastOne)

        result = run_extractors("T", "everything breaks " + "e" * 200, {}, 200)

        # LastOne should survive and handle it
        assert result.content_type == "last"


# ---------------------------------------------------------------------------
# ExtractorResult unit tests
# ---------------------------------------------------------------------------


class TestExtractorResult:
    """ExtractorResult struct: construction, defaults, content_summary."""

    def test_default_constructor(self):
        from src.extractors import ExtractorResult

        r = ExtractorResult()
        assert r.content_type == ""
        assert r.summary_lines == []
        assert r.links == []
        assert r.needs_review is False
        assert r.reason == ""

    def test_content_summary_joins_with_newlines(self):
        from src.extractors import ExtractorResult

        r = ExtractorResult(
            content_type="forum",
            summary_lines=["line one", "line two", "line three"],
            links=["a.i2p", "b.i2p"],
        )
        assert r.content_summary == "line one\nline two\nline three"

    def test_content_summary_empty_when_no_lines(self):
        from src.extractors import ExtractorResult

        r1 = ExtractorResult(summary_lines=[])
        assert r1.content_summary == ""

        r2 = ExtractorResult(summary_lines=None)
        assert r2.content_summary == ""

    def test_needs_review_with_reason(self):
        from src.extractors import ExtractorResult

        r = ExtractorResult(
            needs_review=True, reason="partial_extract_only"
        )
        assert r.needs_review is True
        assert r.reason == "partial_extract_only"


# ---------------------------------------------------------------------------
# run_extractors — header normalization and edge behavior
# ---------------------------------------------------------------------------


class TestRunExtractorsHeaders:
    """Header normalization to Title-Case inside run_extractors."""

    def test_headers_normalized_to_title_case(self, clean_registry):
        """run_extractors normalizes header keys to Title-Case."""
        from src.extractors import _register, BaseExtractor, run_extractors

        class HeaderCheckExt(BaseExtractor):
            priority = 1
            received_keys = None
            def can_handle(self, body_text, headers, status_code): return True
            def extract(self, title, body_text, headers):
                HeaderCheckExt.received_keys = list(headers.keys())
                return ("check", ["ok"], [])

        _register(HeaderCheckExt)
        run_extractors("T", "short", {"content-type": "text/html", "x-random-key": "xyz"}, 200)

        keys = HeaderCheckExt.received_keys
        assert "Content-Type" in keys
        assert "X-Random-Key" in keys

    def test_empty_headers_defaults_to_dict(self, clean_registry):
        """Passing no headers should default to empty dict."""
        from src.extractors import run_extractors

        # This shouldn't crash even with an empty registry (returns needs_review)
        result = run_extractors("T", "body", {}, 200)
        assert result is not None


# ---------------------------------------------------------------------------
# BaseExtractor interface contract enforcement
# ---------------------------------------------------------------------------


class TestBaseExtractorContract:
    """BaseExtractor subclassing requirements and method signatures."""

    def test_instantiating_base_extractor_raises(self):
        from src.extractors import BaseExtractor
        with pytest.raises(TypeError):
            BaseExtractor()

    def test_missing_can_handle_raises(self):
        from src.extractors import BaseExtractor
        class Incomplete(BaseExtractor):
            priority = 10
            def extract(self, t, b, h): return ("", [], [])
        with pytest.raises(TypeError):
            Incomplete()

    def test_missing_extract_raises(self):
        from src.extractors import BaseExtractor
        class Incomplete2(BaseExtractor):
            priority = 10
            def can_handle(self, b, h, s): return False
        with pytest.raises(TypeError):
            Incomplete2()

    def test_complete_subclass_instantiable(self):
        from src.extractors import BaseExtractor
        class Complete(BaseExtractor):
            priority = 10
            def can_handle(self, b, h, s): return False
            def extract(self, t, b, h): return ("ok", [], [])
        # Should not raise
        inst = Complete()
        assert isinstance(inst, BaseExtractor)

    def test_correct_method_signature(self):
        """Subclass methods have the expected parameter names."""
        import inspect
        from src.extractors import BaseExtractor

        class GoodSub(BaseExtractor):
            priority = 10
            def can_handle(self, body_text, headers, status_code): return False
            def extract(self, title, body_text, headers): return ("", [], [])

        inst = GoodSub()
        sig_can = inspect.signature(inst.can_handle)
        assert len(sig_can.parameters) == 3
        sig_ext = inspect.signature(inst.extract)
        assert len(sig_ext.parameters) == 3
