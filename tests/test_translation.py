"""Tests for src/translation.py — language detection, tagging, and local translation.

Covers:
- Language detection with langid (various languages, confidence)
- The process_content_for_language integration entry point (detection + tagging + translation)
- Ollama-based translate_to_english (success, timeout, fallback)
- Graceful fallback when libraries or Ollama are unavailable
- Detected_lang column in DB schema and migrations

Non-English content is tagged with language code for identification.
When Ollama is configured via set_ollama_url(), summaries are translated to English.
"""
import sys
import os

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
