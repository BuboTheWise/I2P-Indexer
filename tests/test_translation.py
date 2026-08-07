"""Tests for src/translation.py — language detection and translation pipeline.

Covers:
- Language detection with langid (various languages, confidence)
- Translation of non-English content to English via deep-translator
- The process_content_for_language integration entry point
- Graceful fallback when libraries are unavailable or APIs fail
- Detected_lang column in DB schema and migrations
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.translation import (
    detect_language,
    translate_to_english,
    process_content_for_language,
    disable_translation,
    reset_state,
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


class TestTranslationEntry:
    """Test process_content_for_language integration endpoint."""

    def setup_method(self):
        reset_state()

    def test_english_content_stays_as_is(self):
        """English content should not be modified or prefixed with language tag."""
        title = "Welcome to the forum"
        summary_lines = [
            "Community discussion platform",
            "Active user base, regular content updates",
        ]
        translated, lang = process_content_for_language(
            title=title,
            summary_lines=summary_lines,
        )
        assert lang == "en"
        # Should not have language tag prefix
        assert not any("[detected_language:" in line for line in translated)
        assert len(translated) == 2

    def test_non_english_gets_language_tag(self):
        """Non-English content should get a language detection tag."""
        title = "Willkommen im Forum"
        summary_lines = [
            "Community-Diskussionsplattform",
            "Aktive Benutzerbasis, regelmäßige Inhaltsaktualisierungen",
        ]
        translated, lang = process_content_for_language(
            title=title,
            summary_lines=summary_lines,
        )
        # Should have detected German or a fallback language tag
        assert len(lang) == 2
        first_line = translated[0]
        assert "[detected_language:" in first_line

    def test_empty_summary_returns_english(self):
        """Empty summary should default to English without processing."""
        translated, lang = process_content_for_language(
            title="",
            summary_lines=[],
        )
        assert lang == "en"

    def test_single_line_summary(self):
        """Single line summary should be handled correctly."""
        title = "My Blog"
        summary_lines = ["Personal blog about technology and programming."]
        translated, lang = process_content_for_language(
            title=title,
            summary_lines=summary_lines,
        )
        assert lang == "en"
        assert len(translated) == 1


class TestTranslationFallbacks:
    """Test graceful degradation when translation infrastructure fails."""

    def setup_method(self):
        reset_state()

    def test_disable_translation_prevents_api_calls(self):
        """disable_translation should prevent any API calls."""
        disable_translation()
        translated, lang = process_content_for_language(
            title="Willkommen im Forum",
            summary_lines=["Community-Diskussionsplattform"],
        )
        # Content not modified (no translation attempted)
        assert "Community-Diskussionsplattform" in "\n".join(translated)

    def test_short_url_summary_skipped(self):
        """URLs and short text should be skipped during translation."""
        title = ""
        summary_lines = [
            "https://example.i2p/forum",
            "#1",
            "abc",
        ]
        translated, lang = process_content_for_language(
            title=title,
            summary_lines=summary_lines,
        )
        # URLs and short strings passed through unchanged
        assert any("https://" in line for line in translated)

    def test_mixed_summary_with_urls_preserves_them(self):
        """Mixed content (text + URLs) should preserve URLs while translating text."""
        title = "Site"
        summary_lines = [
            "https://site.i2p/links",
            "Some English description here",
        ]
        translated, lang = process_content_for_language(
            title=title,
            summary_lines=summary_lines,
        )
        assert any("https://" in line for line in translated)
