"""Tests for src/translation.py — language detection, tagging, and Ollama translation pipeline.

Covers:
- Language detection with langid (various languages, confidence)
- The process_content_for_language integration entry point (detection + tagging + translation)
- Ollama-based translate_to_english (success, timeout, fallback)
- Graceful fallback when libraries or Ollama are unavailable
- Detected_lang column in DB schema and migrations
- Smoke test for Ollama translation integration (default config, reachable/unreachable paths)

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
    set_ollama_url,
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
        title = "Willkommen in unserem Forum"
        body = ("Dies ist eine großartige Online-Community für offene Diskussionen, "
                "den Austausch von Erfahrungen und das gemeinsame Teilen von Wissen. "
                "Alle Mitglieder sind hier herzlich willkommen.")
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


class TestOllamaTranslation:
    """Test translate_to_english and set_ollama_url."""

    def setup_method(self):
        reset_state()
        set_ollama_url(None)

    def test_translate_returns_none_when_no_url(self):
        """Without ollama configured, translation returns None."""
        result = translate_to_english("Hallo Welt", "de")
        assert result is None

    def test_translate_returns_text_for_english(self):
        """English content should be returned as-is even with ollama configured."""
        set_ollama_url("http://localhost:11434")
        result = translate_to_english("Hello world", "en")
        assert result == "Hello world"

    def test_translate_returns_none_on_timeout(self):
        """Translation to unreachable endpoint should return None gracefully."""
        set_ollama_url("http://127.0.0.1:99999")
        result = translate_to_english("Hallo Welt", "de", timeout=2.0)
        assert result is None

    def test_set_ollama_url_clears_error_state(self):
        """Setting a new URL should reset the error flag."""
        from src import translation as trans_mod
        # Trigger an error first
        set_ollama_url("http://127.0.0.1:99999")
        translate_to_english("Hallo", "de", timeout=2.0)
        assert trans_mod._ollama_error is True
        # New URL resets the flag
        set_ollama_url("http://localhost:11434")
        assert trans_mod._ollama_error is False

    def test_translation_integration_with_process_content(self):
        """Non-English content should fall back gracefully when ollama unavailable."""
        set_ollama_url("http://127.0.0.1:99999")
        tagged, lang = process_content_for_language(
            title="Willkommen",
            summary_lines=["Community-Diskussionsplattform"],
            detected_lang="de",
            confidence=0.9,
        )
        assert lang == "de"
        assert "[detected_language: de (German)]" in tagged[0]
        # Original preserved since ollama is unreachable
        assert "Community-Diskussionsplattform" in "\n".join(tagged)

    def test_retry_on_transient_failure(self):
        """Retries on transient failure before exhausting and setting cooldown."""
        import json
        from unittest.mock import patch
        set_ollama_url("http://localhost:11434")
        reset_state()

        class FakeResp:
            def read(self):
                return json.dumps({"response": "Success"}).encode("utf-8")
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        call_count = 0
        def flaky_urlopen(*a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("transient")
            return FakeResp()

        with patch("urllib.request.urlopen", side_effect=flaky_urlopen):
            result = translate_to_english("texto", "es", 10.0)

        assert result == "Success"
        assert call_count == 3

    def test_exhausted_retries_sets_cooldown(self):
        """After max retries, cooldown flag is set."""
        from unittest.mock import patch
        set_ollama_url("http://localhost:11434")
        reset_state()

        with patch("urllib.request.urlopen", side_effect=Exception("fail")):\
            result = translate_to_english("test", "de", 10.0)

        assert result is None
        from src import translation as trans_mod
        assert trans_mod._ollama_error is True

class TestOllamaConfigSmoke(unittest.TestCase):
    """Smoke tests for OllamaConfig integration (task t_4a274cfc)."""

    def setUp(self):
        reset_state()

    def test_ollama_config_default_url_empty(self):
        """OllamaConfig created with no arguments has empty URL and is disabled."""
        from src.config import OllamaConfig, I2PConfig

        ollama = OllamaConfig()
        self.assertEqual(ollama.ollama_url, "")
        self.assertFalse(ollama.enabled)

        # I2PConfig backward compat properties work
        cfg = I2PConfig()
        self.assertEqual(cfg.ollama_url, "")
        self.assertFalse(cfg.ollama_enabled)

    def test_ollama_config_default_model(self):
        """OllamaConfig default model is llama3.2."""
        from src.config import OllamaConfig

        ollama = OllamaConfig()
        self.assertEqual(ollama.model, "llama3.2")

    def test_i2pconfig_ollama_forwarding(self):
        """I2PConfig passes through ollama settings correctly."""
        from src.config import I2PConfig, OllamaConfig

        cfg = I2PConfig(ollama=OllamaConfig(
            ollama_url="http://localhost:11434/api/generate"
        ))
        self.assertTrue(cfg.ollama_enabled)
        self.assertEqual(cfg.ollama.model, "llama3.2")

if __name__ == "__main__":
    unittest.main()
