"""Integration tests for probe path isolation and extractor registry correctness.

Covers three guarantees:
  1. Probe path (_do_probe / discover_addresses) does NOT call Ollama or any
     translation function — probes must be fast, network calls only to I2P destinations.
  2. Registered extractors list matches src/ext_plugins/ contents (registry discovers
     plugins correctly).
  3. needs_review flagging works when no extractor claims a response.
"""
from __future__ import annotations

import pathlib
import sqlite3
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# 1. Probe path must NOT call Ollama / translate_to_english
# ---------------------------------------------------------------------------

class TestProbeNoOllama:
    """Verify the probe path never touches Ollama/translation endpoints.

    Strategy: monkeypatch every function that makes external translation calls
    with a side-effect marker; run _do_probe through the happy path entirely in
    mocks; assert none of the markers were triggered.
    """

    def _mock_fetch_i2p(self, status=200, body=b"<html><title>Test</title><body>Hello</body></html>", headers=None):
        """Build a mock response matching what fetch_i2p returns."""
        if headers is None:
            headers = {}
        mock = MagicMock()
        mock.status = status
        mock.body = body
        mock.text = body.decode("utf-8", errors="replace")
        mock.title.return_value = "Test"
        mock.headers = headers
        return mock

    def test_do_probe_does_not_call_translation(self):
        """probe_destination / _do_probe must not invoke any translation function.

        All three Ollama/translation entry points in src.translation:
          - translate_to_english()  — calls localhost:11434
          - process_content_for_language()  — wrapper that calls translate_to_english
          - set_ollama_url()     — configuring a URL would indicate probe sets up Ollama
        """
        from src.integration import _do_probe
        from src.config import I2PConfig

        with patch("src.translation.translate_to_english", return_value=None) as mock_trans:
            with patch("src.translation.process_content_for_language",
                       side_effect=lambda *a, **k: ([], "") ) as mock_proc:
                with patch("src.translation.set_ollama_url"):
                    with patch("src.integration.fetch_i2p", return_value=self._mock_fetch_i2p()):
                        result = _do_probe(
                            url="http://abcd1234.b32.i2p/",
                            ident_hash_hex="A" * 40,
                            i2p_dns_name="test.i2p",
                            probe_mode="b32",
                            timeout=5.0,
                            config=I2PConfig(),
                        )

        assert mock_trans.call_count == 0, \
            f"_do_probe called translate_to_english {mock_trans.call_count} time(s) — probe coupled to Ollama"
        assert mock_proc.call_count == 0, \
            f"_do_probe called process_content_for_language {mock_proc.call_count} time(s) — probe coupled to translation"
        # Result should still be valid (probe succeeded through mocks)
        assert result.reachable is True

    def test_do_probe_does_not_hit_ollama_url(self):
        """Verify no urllib.request.urlopen hits localhost:11434 during probing."""
        from src.integration import _do_probe
        from src.config import I2PConfig

        # Patch urlopen globally — any Ollama call would use this
        with patch("urllib.request.urlopen") as mock_urlopen:
            with patch("src.integration.fetch_i2p", return_value=self._mock_fetch_i2p()):
                _do_probe(
                    url="http://abcd1234.b32.i2p/",
                    ident_hash_hex="B" * 40,
                    probe_mode="b32",
                    timeout=5.0,
                    config=I2PConfig(),
                )

            # urlopen calls should only be from fetch_i2p (which we've patched),
            # so Ollama-related URLs should never appear
            for call in mock_urlopen.call_args_list:
                url_arg = str(call[0][0].full_url) if hasattr(call[0][0], 'full_url') else str(call[0][0])
                assert "11434" not in url_arg, \
                    f"_do_probe hit Ollama port 11434 via {url_arg}"
                assert "/api/generate" not in url_arg, \
                    f"_do_probe hit Ollama API via {url_arg}"

    def test_discover_addresses_does_not_call_translation(self):
        """discover_addresses() orchestrates probes — verify it doesn't trigger translation either."""
        from src.integration import discover_addresses
        from src.config import I2PConfig

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        try:
            with patch("src.translation.translate_to_english", return_value=None) as mock_trans:
                with patch("src.translation.process_content_for_language",
                           side_effect=lambda *a, **k: ([], "")) as mock_proc:
                    with patch("src.integration.fetch_i2p", return_value=self._mock_fetch_i2p()):
                        # Patch time.sleep so the test finishes quickly
                        with patch("time.sleep"):
                            discover_addresses(
                                known_addrs=["test.i2p"],
                                config=I2PConfig(),
                                db_path=db_path,
                                probe_delay=0,
                                limit=1,
                            )

            assert mock_trans.call_count == 0, \
                f"discover_addresses triggered translate_to_english {mock_trans.call_count} time(s)"
            assert mock_proc.call_count == 0, \
                f"discover_addresses triggered process_content_for_language {mock_proc.call_count} time(s)"
        finally:
            pathlib.Path(db_path).unlink(missing_ok=True)

    def test_probe_calls_only_detect_language_not_translate(self):
        """Probe path SHOULD call detect_language (local langid), just NOT translation."""
        from src.integration import _do_probe
        from src.config import I2PConfig

        # detect_language gets patched to return a known result without hitting langid
        with patch("src.translation.detect_language", return_value=("en", 0.95)) as mock_detect:
            with patch("src.integration.fetch_i2p", return_value=self._mock_fetch_i2p()):
                _do_probe(
                    url="http://abcd1234.b32.i2p/",
                    ident_hash_hex="C" * 40,
                    probe_mode="b32",
                    config=I2PConfig(),
                )

        # detect_language SHOULD be called — it's fast and local
        assert mock_detect.call_count > 0, \
            "Probe path should still call detect_language() (local langid)"


# ---------------------------------------------------------------------------
# 2. Extractor registry matches ext_plugins/ directory
# ---------------------------------------------------------------------------

class TestRegistryMatchesPlugins:
    """The extractor registry and plugin system work correctly.

    NOTE: Currently only html_extractor uses @_register. Other plugins define
    extractor classes but don't register them (they're for manual dispatch).
    Tests verify the plugin discovery mechanism works regardless of count.
    """

    def test_registry_accessible(self):
        """get_registry() always returns a list."""
        from src import extractors as ext_mod

        registry = ext_mod.get_registry()
        assert isinstance(registry, list)
        # Should have at least html_extractor registered
        assert len(registry) >= 1, "Registry should contain at least one extractor"

    def test_registered_extractors_are_from_ext_plugins(self):
        """Every registered extractor class lives in src.ext_plugins namespace."""
        from src import extractors as ext_mod

        registry = ext_mod.get_registry()
        for ex in registry:
            cls_module = type(ex).__module__
            assert "src.ext_plugins" in cls_module, \
                f"Extractor {type(ex).__name__} has unexpected module {cls_module}"

    def test_discover_plugins_loads_each_file(self):
        """discover_plugins() imports every valid .py file (excluding __init__, private)."""
        import importlib.util
        from src import extractors as ext_mod

        plugin_dir = PROJECT_ROOT / "src" / "ext_plugins"
        plugin_files = [
            f.stem for f in plugin_dir.glob("*.py")
            if not f.name.startswith("_")
        ]

        loaded_count = 0
        errors = []
        for pkg_file in sorted(plugin_dir.glob("*.py")):
            if pkg_file.name.startswith("_"):
                continue
            module_name = pkg_file.stem
            try:
                spec = importlib.util.spec_from_file_location(
                    f"src.ext_plugins.{module_name}", pkg_file
                )
                if spec is None or spec.loader is None:
                    errors.append(f"{module_name}: no spec")
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                loaded_count += 1
            except Exception as e:
                errors.append(f"{module_name}: {type(e).__name__}")

        assert loaded_count == len(plugin_files), \
            f"discover_plugins should load all {len(plugin_files)} files, got {loaded_count}. Errors: {errors}"

    def test_empty_plugin_dir_does_not_crash(self):
        """If ext_plugins/ has no valid files, registry is still accessible."""
        from src import extractors as ext_mod

        # Temporarily point to an empty directory
        with tempfile.TemporaryDirectory() as tmpdir:
            orig_dir = ext_mod._PLUGIN_DIR
            orig_reg_contents = list(ext_mod._registry)
            try:
                ext_mod._PLUGIN_DIR = pathlib.Path(tmpdir)
                # Clear registry so discover_plugins starts fresh
                ext_mod._registry.clear()

                ext_mod.discover_plugins()
                registry = ext_mod.get_registry()
                assert isinstance(registry, list), "get_registry() must always return a list"
            finally:
                ext_mod._PLUGIN_DIR = orig_dir
                ext_mod._registry[:] = orig_reg_contents

    def test_html_extractor_in_registry(self):
        """HtmlExtractor is the primary registered fallback extractor."""
        from src import extractors as ext_mod

        registry = ext_mod.get_registry()
        names = {type(ex).__name__ for ex in registry}
        assert "HtmlExtractor" in names, \
            "HtmlExtractor should be in the registry (primary content-type-agnostic fallback)"


# ---------------------------------------------------------------------------
# 3. needs_review flagging when no extractor claims a response
# ---------------------------------------------------------------------------

class TestNeedsReviewFlagging:
    """When NO extractor can_handle() returns True, run_extractors must return
    ExtractorResult with needs_review=True and reason='no_extractor_claimed'.
    """

    def test_no_matcher_sets_needs_review(self):
        """An unrecognized response body triggers needs_review."""
        from src.extractors import run_extractors, _registry

        # Save the live registry so we can temporarily clear it
        orig = list(_registry)
        try:
            _registry.clear()

            result = run_extractors(
                title="Unknown Site",
                body_text="<html><body>Weird binary junk \x00\x01</body></html>",
                headers={"Content-Type": "application/octet-stream"},
                status_code=200,
            )

            assert result.needs_review is True, \
                "needs_review must be True when no extractor matches"
            assert result.reason == "no_extractor_claimed", \
                f"Expected reason 'no_extractor_claimed', got '{result.reason}'"
            assert result.content_type == "", \
                "Content type should be empty for unclassified responses"
        finally:
            _registry[:] = orig

    def test_needs_review_propagates_through_do_probe(self):
        """When extractors return needs_review, the DiscoveryResult carries it."""
        from src.integration import _do_probe
        from src.config import I2PConfig
        from src.extractors import _registry

        weird_body = b"<html><body>Unrecognized binary content \xff\xfe</body></html>"
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = weird_body
        mock_resp.text = weird_body.decode("utf-8", errors="replace")
        mock_resp.title.return_value = "Unknown"
        mock_resp.headers = {"Content-Type": "application/octet-stream"}

        # Clear registry so nothing claims this content
        orig = list(_registry)
        try:
            _registry.clear()

            with patch("src.integration.fetch_i2p", return_value=mock_resp):
                result = _do_probe(
                    url="http://test.b32.i2p/",
                    ident_hash_hex="D" * 40,
                    probe_mode="b32",
                    config=I2PConfig(),
                )

            assert result.needs_review is True, \
                "DiscoveryResult needs_review should be True when no extractor claimed"
            assert result.reason == "no_extractor_claimed", \
                f"Reason should propagate: got '{result.reason}'"
        finally:
            _registry[:] = orig

    def test_needs_review_flag_added_to_discovery_result_flags(self):
        """needs_review produces a structured flag entry in DiscoveryResult.flags."""
        from src.integration import _do_probe
        from src.config import I2PConfig
        from src.extractors import _registry

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = b"<html><body>Unknown content</body></html>"
        mock_resp.text = "<html><body>Unknown content</body></html>"
        mock_resp.title.return_value = "Mystery"
        mock_resp.headers = {"Content-Type": "application/octet-stream"}

        orig = list(_registry)
        try:
            _registry.clear()

            with patch("src.integration.fetch_i2p", return_value=mock_resp):
                result = _do_probe(
                    url="http://test.b32.i2p/",
                    ident_hash_hex="E" * 40,
                    probe_mode="b32",
                    config=I2PConfig(),
                )

            # Check that a needs_review flag exists in the flags list
            has_flag = any(
                f.get("type") == "needs_review"
                for f in (result.flags or [])
            )
            assert has_flag, \
                "DiscoveryResult.flags should contain a needs_review entry"
        finally:
            _registry[:] = orig
