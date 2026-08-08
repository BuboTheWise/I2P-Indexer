"""Tests for src/translation.py — language detection, tagging, and Ollama translation pipeline.

Covers:
- Language detection with langid (various languages, confidence)
- The process_content_for_language integration entry point (detection + tagging only)
- Graceful fallback when libraries are unavailable
- Detected_lang column in DB schema and migrations
- Smoke test for Ollama translation integration (default config, reachable/unreachable paths)

Translation via deep-translator was removed (NFR-07 privacy mandate).
Non-English content is tagged with language code for identification.
Optional Ollama translation routes through a local /api/generate endpoint.
"""
import json
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.translation import (
    detect_language,
    process_content_for_language,
    reset_state,
    translate_to_english,
)


class TestLanguageDetection:
    """Test langid-based language detection."""

    def test_detect_english(self):
        """English content should be detected as English."""
        title = "Welcome to our forum"
        body = "This is a great community for open discussion and sharing knowledge."
        lang, conf = detect_language(title, body)
        assert lang == "en", f"Expected 'en', got '{lang}'"

    def test_detect_german(self):
        """German content should be detected as German."""
        title = "Willkommen im Forum"
        body = "Dies ist eine großartige Community für offene Diskussionen."
        lang, conf = detect_language(title, body)
        assert lang == "de", f"Expected 'de', got '{lang}'"

    def test_detect_japanese(self):
        """Japanese content should be detected as Japanese."""
        title = "フォーラムへようこそ"
        body = "これはオープンな議論と知識共有のための素晴らしいコミュニティです。"
        lang, conf = detect_language(title, body)
        assert lang == "ja", f"Expected 'ja', got '{lang}'"

    def test_detect_chinese(self):
        """Chinese content should be detected as Chinese."""
        title = "欢迎来到论坛"
        body = "这是一个伟大的社区，可以进行公开讨论和知识共享。"
        lang, conf = detect_language(title, body)
        assert lang == "zh", f"Expected 'zh', got '{lang}'"

    def test_detect_russian(self):
        """Russian content should be detected as Russian."""
        title = "Добро пожаловать на форум"
        body = "Это отличное сообщество для открытых обсуждений и обмена знаниями."
        lang, conf = detect_language(title, body)
        assert lang == "ru", f"Expected 'ru', got '{lang}'"

    def test_short_text_defaults_to_english(self):
        """Very short text should default to English (unreliable detection)."""
        title = ""
        body = "foo bar baz"
        lang, conf = detect_language(title, body)
        assert lang == "en", f"Expected 'en' for short text, got '{lang}'"

    def test_confidence_threshold(self):
        """Confidence below threshold should still return the detected language."""
        title = "Hi there"
        body = "Mixed content: hallo ciao你好こんにちは"
        lang, conf = detect_language(title, body)
        # Just verify we get a valid result without crashing
        assert len(lang) == 2
        assert isinstance(conf, float)


class TestLanguageTaggingEntry:
    """Test process_content_for_language — detection + tagging only."""

    def setup_method(self):
        reset_state()

    def test_english_content_stays_as_is(self):
        """English content should not be modified or prefixed with language tag."""
        title = "Welcome to the forum"
        summary_lines = [
            "Community discussion platform",
            "Active user base, regular content updates",
        ]
        tagged, lang = process_content_for_language(
            title=title,
            summary_lines=summary_lines,
        )
        assert lang == "en"
        # Should not have language tag prefix
        assert not any("[detected_language:" in line for line in tagged)
        assert len(tagged) == 2

    def test_non_english_gets_language_tag(self):
        """Non-English content should get a language detection tag."""
        title = "Willkommen im Forum"
        summary_lines = [
            "Community-Diskussionsplattform",
            "Aktive Benutzerbasis, regelmäßige Inhaltsaktualisierungen",
        ]
        tagged, lang = process_content_for_language(
            title=title,
            summary_lines=summary_lines,
        )
        # Should have detected German or a fallback language tag
        assert len(lang) == 2
        first_line = tagged[0]
        assert "[detected_language:" in first_line

    def test_non_english_content_preserved(self):
        """Non-English content should be preserved as-is (no translation)."""
        title = "Willkommen im Forum"
        summary_lines = ["Community-Diskussionsplattform"]
        tagged, lang = process_content_for_language(
            title=title,
            summary_lines=summary_lines,
        )
        # Original text unchanged — only a tag was prepended
        assert "Community-Diskussionsplattform" in "\n".join(tagged)

    def test_empty_summary_returns_english(self):
        """Empty summary should default to English without processing."""
        tagged, lang = process_content_for_language(
            title="",
            summary_lines=[],
        )
        assert lang == "en"

    def test_single_line_summary(self):
        """Single line summary should be handled correctly."""
        title = "My Blog"
        summary_lines = ["Personal blog about technology and programming."]
        tagged, lang = process_content_for_language(
            title=title,
            summary_lines=summary_lines,
        )
        assert lang == "en"
        assert len(tagged) == 1


class TestTaggingFallbacks:
    """Test graceful degradation when detection fails."""

    def setup_method(self):
        reset_state()

    def test_short_url_summary_skipped(self):
        """URLs and short text should be passed through unchanged."""
        title = ""
        summary_lines = [
            "https://example.i2p/forum",
            "#1",
            "abc",
        ]
        tagged, lang = process_content_for_language(
            title=title,
            summary_lines=summary_lines,
        )
        # URLs and short strings passed through unchanged
        assert any("https://" in line for line in tagged)

    def test_mixed_summary_with_urls_preserves_them(self):
        """Mixed content (text + URLs) should preserve URLs while tagging text."""
        title = "Site"
        summary_lines = [
            "https://site.i2p/links",
            "Some English description here",
        ]
        tagged, lang = process_content_for_language(
            title=title,
            summary_lines=summary_lines,
        )
        assert any("https://" in line for line in tagged)


class TestOllamaTranslationSmoke(unittest.TestCase):
    """Smoke tests for Ollama translation integration (task t_4a274cfc).

    Verifies:
    1. OllamaConfig is created with default URL (empty/disabled by default)
    2. translate_to_english() returns translated text when Ollama is reachable
    3. Ollama unavailable is handled gracefully without crashing the probe pipeline
    """

    def setUp(self):
        reset_state()

    # -- (1) OllamaConfig default URL ----------------------------------------

    def test_ollama_config_default_url_empty(self):
        """OllamaConfig created with no arguments has empty URL and is disabled."""
        from src.config import OllamaConfig, I2PConfig

        ollama = OllamaConfig()
        self.assertEqual(ollama.ollama_url, "")
        self.assertFalse(ollama.enabled)

        # Also verify I2PConfig embeds this correctly
        cfg = I2PConfig()
        self.assertEqual(cfg.ollama_url, "")
        self.assertFalse(cfg.ollama_enabled)

    def test_ollama_config_default_model(self):
        """OllamaConfig default model is 'llama3.2'."""
        from src.config import OllamaConfig

        ollama = OllamaConfig()
        self.assertEqual(ollama.model, "llama3.2")

    # -- (2) translate_to_english returns text when Ollama reachable ----------

    @patch("urllib.request.urlopen")
    def test_translate_returns_text_when_reachable(self, mock_urlopen):
        """translate_to_english() returns translated text on successful response."""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "response": "This is the translation of the German text."
        }).encode()
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        result = translate_to_english(
            text="Das ist der deutsche Text.",
            source_lang="de",
            ollama_url="http://localhost:11434/api/generate",
            model="llama3.2",
        )

        self.assertEqual(result, "This is the translation of the German text.")

    # -- (3) Ollama unavailable handled gracefully --------------------------

    @patch("urllib.request.urlopen")
    def test_translate_handles_connection_refused(self, mock_urlopen):
        """Connection refused returns None — doesn't crash the pipeline."""
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")

        result = translate_to_english(
            text="Some non-English content",
            source_lang="ru",
            ollama_url="http://localhost:11434/api/generate",
        )
        self.assertIsNone(result)

    @patch("urllib.request.urlopen")
    def test_translate_handles_timeout(self, mock_urlopen):
        """Timeout returns None — doesn't crash the pipeline."""
        import socket
        mock_urlopen.side_effect = socket.timeout("timed out")

        result = translate_to_english(
            text="Test content",
            source_lang="ja",
            ollama_url="http://localhost:11434/api/generate",
        )
        self.assertIsNone(result)

    @patch("urllib.request.urlopen")
    def test_translate_handles_bad_json(self, mock_urlopen):
        """Malformed JSON from Ollama returns None — doesn't crash the pipeline."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"not valid json at all {"
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        result = translate_to_english(
            text="Test content here",
            source_lang="de",
            ollama_url="http://localhost:11434/api/generate",
        )
        self.assertIsNone(result)

    @patch("urllib.request.urlopen")
    def test_probe_pipeline_survives_ollama_failure(self, mock_urlopen):
        """Simulate integration.py probe pipeline: translation failure never
        breaks a probe. The try/except block catches all errors and preserves
        original content."""
        import urllib.error
        from src.config import I2PConfig, OllamaConfig

        # Simulate Ollama being down
        mock_urlopen.side_effect = urllib.error.URLError("connection refused")

        config = I2PConfig(ollama=OllamaConfig(
            ollama_url="http://localhost:11434/api/generate"
        ))
        detected_lang = "de"
        tagged_summary_lines = [
            "[detected_language: de (German)]",
            "Dies ist ein deutscher Seiteninhalt.",
        ]

        # Replicate what integration.py does for translation:
        ollama_url_attr = getattr(config, "ollama_url", "")
        if ollama_url_attr and detected_lang != "en":
            try:
                combined_summary = "\n".join(tagged_summary_lines)
                translated = translate_to_english(
                    text=combined_summary,
                    source_lang=detected_lang,
                    ollama_url=ollama_url_attr,
                )
                if translated:
                    tagged_summary_lines = [
                        f"[translated_from: {detected_lang}]",
                        translated,
                    ]
            except Exception:
                pass  # Translation failure should never break a probe

        # Pipeline survived — original content preserved
        self.assertTrue(len(tagged_summary_lines) >= 1)
        joined = " ".join(tagged_summary_lines).lower()
        self.assertTrue(
            any(word in joined for word in ["dieser", "deutscher"]),
            f"Original German content should be preserved: {joined}",
        )

    def test_english_short_circuits_without_request(self):
        """English source language returns None immediately — no HTTP request."""
        result = translate_to_english(
            text="Hello world",
            source_lang="en",
            ollama_url="http://localhost:11434/api/generate",
        )
        self.assertIsNone(result)

    def test_empty_url_skips_translation(self):
        """Empty ollama_url (default config) returns None immediately."""
        result = translate_to_english(
            text="Some content here",
            source_lang="de",
            ollama_url="",
        )
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
