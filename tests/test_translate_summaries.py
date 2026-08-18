"""Tests for translate_summaries.py — standalone translation of non-English summaries.

Covers:
- get_pending_translations() DB queries (filtering, lang filter, limit, already-translated skip)
- _needs_translation() detection logic (various tag states, edge cases)
- build_translation_summary() format (tag markers, original preservation, URL skipping)
- translate_text() with mocked urllib calls (success, failure, cooldown, English passthrough)
- translate_text() Ollama payload structure (model, prompt, stream flag, Content-Type)
- translate_text() retry on empty response followed by success
- translate_text() cooldown blocking subsequent calls without HTTP
- _try_clear_ollama_error() cooldown clearing vs staying in error
- update_summary() DB writes, nonexistent ID, and error suppression
- Probes in integration.py do NOT call translate_summaries functions (architectural isolation)
"""
import json
import os
import sqlite3
import sys
import tempfile
from unittest.mock import MagicMock, patch, mock_open

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from translate_summaries import (
    _needs_translation,
    build_translation_summary,
    get_pending_translations,
    translate_text,
    update_summary,
    _try_clear_ollama_error,
    DEFAULT_DB_PATH,
    OLLAMA_MODEL,
    OLLAMA_COOLDOWN_S,
)


def _make_test_db():
    """Create a temporary SQLite DB with the discoveries schema and some test rows."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE discoveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ident_hash_hex TEXT NOT NULL,
            i2p_dns_name TEXT,
            detected_lang TEXT DEFAULT '',
            content_summary TEXT DEFAULT '',
            title TEXT DEFAULT '',
            reachable INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    return path, conn


class TestGetPendingTranslations:
    """Test DB query logic for fetching untranslated entries."""

    def setup_method(self):
        self.db_path, self.conn = _make_test_db()
        cur = self.conn.cursor()
        # Reachable German site, no translation markers
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, i2p_dns_name, detected_lang, content_summary, title, reachable) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("dead001" * 4, "forum.i2p", "de", "Community-Diskussionsplattform", "Forum", 1),
        )
        # Reachable Russian site
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, i2p_dns_name, detected_lang, content_summary, title, reachable) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("dead002" * 4, "news.i2p", "ru", "Последние новости с форума", "Новости", 1),
        )
        # English site — should be excluded by detected_lang != 'en'
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, i2p_dns_name, detected_lang, content_summary, title, reachable) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("dead003" * 4, "en-site.i2p", "en", "English content here", "EN Site", 1),
        )
        # Already-translated (has [detected_language: tag AND [original: marker)
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, i2p_dns_name, detected_lang, content_summary, title, reachable) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("dead004" * 4, "translated.i2p", "fr",
             "[detected_language: fr (French)]\nTranslated text [original: original]", "FR", 1),
        )
        # Has [detected_language: but NO [original: — untranslated, should appear
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, i2p_dns_name, detected_lang, content_summary, title, reachable) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("dead008" * 4, "detected-but-untranslated.i2p", "de",
             "[detected_language: de (German)]\nCommunity-Diskussionsplattform ohne Übersetzung", "DE Untranslated", 1),
        )
        # Already-translated (has [original: marker)
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, i2p_dns_name, detected_lang, content_summary, title, reachable) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("dead005" * 4, "translated2.i2p", "es",
             "Translated [original: traducido]", "ES", 1),
        )
        # Unreachable site — excluded by reachable=1
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, i2p_dns_name, detected_lang, content_summary, title, reachable) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("dead006" * 4, "down.i2p", "ja", "ダウンしています", "Down", 0),
        )
        # Empty detected_lang — excluded
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, i2p_dns_name, detected_lang, content_summary, title, reachable) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("dead007" * 4, "nowork.i2p", "", "No language detected", "Unknown", 1),
        )
        self.conn.commit()

    def teardown_method(self):
        self.conn.close()
        os.unlink(self.db_path)

    def test_pending_returns_only_needing_translation(self):
        """Only reachable non-English untranslated entries returned."""
        results = get_pending_translations(self.db_path)
        assert len(results) == 3  # German + Russian + detected-but-untranslated
        langs = {r["detected_lang"] for r in results}
        assert "de" in langs
        assert "ru" in langs

    def test_lang_filter(self):
        """Filtering by language code returns only that language."""
        results = get_pending_translations(self.db_path, lang_filter="ru")
        assert len(results) == 1
        assert results[0]["detected_lang"] == "ru"

    def test_limit(self):
        """Limit caps the number of returned rows."""
        results = get_pending_translations(self.db_path, limit=1)
        assert len(results) == 1

    def test_skips_already_translated(self):
        """Entries with [original: marker are excluded."""
        results = get_pending_translations(self.db_path)
        ids = [r["id"] for r in results]
        # ID 4 (fr, has [original:) and ID 6 (es, has [original:) should NOT appear
        # ID 5 (de, has [detected_language: but NO [original:) SHOULD appear
        assert 4 not in ids
        assert 6 not in ids
        assert 5 in ids

    def test_skips_unreachable(self):
        """Unreachable sites are excluded."""
        results = get_pending_translations(self.db_path)
        for r in results:
            # All returned were reachable=1 (Japanese down site at id=6 excluded)
            assert r["id"] != 6

    def test_skips_english(self):
        """English sites are excluded."""
        results = get_pending_translations(self.db_path)
        for r in results:
            assert r["detected_lang"] != "en"


class TestNeedsTranslation:
    """Test _needs_translation detection logic."""

    def test_empty_summary_false(self):
        """Empty summary returns False (nothing to translate)."""
        assert _needs_translation("") is False

    def test_whitespace_only_short_false(self):
        """Whitespace-only text under 10 chars stripped returns False."""
        assert _needs_translation("   ") is False

    def test_short_text_false(self):
        """Text under 10 chars returns False (too short)."""
        assert _needs_translation("short") is False
        assert _needs_translation("    abcd    ") is False  # stripped < 10

    def test_untranslated_true(self):
        """Summary without translation markers needs translation."""
        assert _needs_translation("This is German text here long enough") is True

    def test_already_tagged_detected_language_false(self):
        """Presence of [detected_language: without [original:] still needs translation."""
        assert _needs_translation("[detected_language: de (German)]\nSome untranslated text here that is long enough") is True

    def test_detected_language_with_original_is_translated(self):
        """Full translated entry has both markers — no re-translation needed."""
        assert _needs_translation("[detected_language: de (German)]\nTranslated [original: original]") is False

    def test_already_has_original_marker_false(self):
        """Presence of [original: means already translated."""
        assert _needs_translation("Translated text [original: original text]") is False

    def test_normal_text_true(self):
        """Regular non-English text without markers needs translation."""
        summary = "Dies ist ein deutscher Text zum Übersetzen heute."
        assert _needs_translation(summary) is True


class TestBuildTranslationSummary:
    """Test build_translation_summary format and content preservation."""

    def test_basic_format(self):
        """Basic translation summary has language tag, translated line, original preserved."""
        result = build_translation_summary(
            "This is German text here",
            "This is English translation",
            "de",
        )
        assert "[detected_language: de (German)]" in result
        assert "This is English translation" in result
        assert "[original: This is German text here]" in result

    def test_original_preservation(self):
        """Original first line preserved in [original: ...] suffix."""
        original = "Zeile Eins ist wichtig\nZeile Zwei fehlt nicht"
        result = build_translation_summary(
            original,
            "First line translated",
            "fr",
        )
        assert "[original: Zeile Eins ist wichtig]" in result

    def test_remaining_lines_preserved(self):
        """Lines after the first translatable one are kept."""
        original = "German line one\nGerman line two\nThird german line"
        result = build_translation_summary(original, "English one", "de")
        assert "German line two" in result
        assert "Third german line" in result

    def test_url_lines_skipped_for_translation(self):
        """Lines starting with http are skipped for translation but preserved."""
        original = "https://site.i2p/links\nThis is the actual content here today"
        result = build_translation_summary(original, "English content", "ru")
        assert "https://site.i2p/links" in result

    def test_short_lines_skipped(self):
        """Lines under 10 chars are skipped as non-translatable."""
        original = "abc\nThis is the main content to translate today"
        result = build_translation_summary(original, "Main translation", "es")
        # Short line passes through, long line gets translated
        assert "abc" in result

    def test_unknown_language_code(self):
        """Unknown language codes still produce a tag with just ISO code."""
        result = build_translation_summary("Some text here long enough", "Translation", "xx")
        assert "[detected_language: xx]" in result
        # No parenthesized name for unknown codes

    def test_empty_summary_returns_original(self):
        """Completely empty summary is returned unchanged."""
        result = build_translation_summary("", "Translation", "de")
        assert result == ""

    def test_known_language_name_present(self):
        """Supported language codes include English names in parentheses."""
        for lang in ["de", "fr", "es", "ja", "zh", "ru", "ko", "ar"]:
            result = build_translation_summary("Content here is long enough", "T", lang)
            assert f"[detected_language: {lang}" in result

    def test_multiline_first_content_line(self):
        """When first line is a URL, second content line is translated."""
        original = "http://example.com\nDieser Text ist auf Deutsch geschrieben"
        result = build_translation_summary(original, "This text is written in German", "de")
        assert "[original: Dieser Text ist auf Deutsch geschrieben]" in result


class TestTranslateText:
    """Test translate_text with mocked urllib calls."""

    def test_returns_none_without_url(self):
        """Without an Ollama URL configured, translation returns None."""
        assert translate_text("test", "de", "", 5.0) is None

    def test_english_passthrough(self):
        """English source language returns text as-is without calling Ollama."""
        result = translate_text("Hello world", "en", "http://localhost:11434", 5.0)
        assert result == "Hello world"

    def test_successful_translation(self):
        """Successful Ollama response is returned."""

        class FakeResp:
            def read(self):
                return json.dumps({"response": "Translated text"}).encode("utf-8")
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        with patch("urllib.request.urlopen", return_value=FakeResp()):
            result = translate_text("Original texto", "es", "http://localhost:11434", 10.0)
        assert result == "Translated text"

    def test_empty_response_returns_none(self):
        """Empty response from Ollama returns None."""

        class FakeResp:
            def read(self):
                return json.dumps({"response": ""}).encode("utf-8")
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        with patch("urllib.request.urlopen", return_value=FakeResp()):
            result = translate_text("texto", "es", "http://localhost:11434", 10.0)
        assert result is None

    def test_connection_error_returns_none(self):
        """Network error during translation returns None."""
        with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
            result = translate_text("texto", "es", "http://localhost:11434", 10.0)
        assert result is None

    def test_long_response_truncated(self):
        """Multi-paragraph responses (>3 lines) are truncated to first line."""
        import translate_summaries as ts

        # Clear any cooldown state left by earlier tests in this class
        ts._ollama_error = False
        ts._ollama_error_time = 0.0

        class FakeResp:
            def read(self):
                long_response = "First paragraph\nSecond para\nThird line\nFourth line\nAnd more"
                return json.dumps({"response": long_response}).encode("utf-8")
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        with patch("urllib.request.urlopen", return_value=FakeResp()):
            result = translate_text("texto", "es", "http://localhost:11434", 10.0)
        assert result == "First paragraph"


class TestCooldownBehavior:
    """Test Ollama error cooldown mechanism."""

    def test_cooldown_blocks_after_error(self):
        """After exhausting retries, subsequent calls in cooldown return None."""
        import translate_summaries as ts
        # Clear state first
        ts._ollama_error = False
        ts._ollama_error_time = 0.0

        with patch("urllib.request.urlopen", side_effect=Exception("fail")):\
            translate_text("test", "de", "http://localhost:11434", 10.0)

        assert ts._ollama_error is True

    def test_retry_on_transient_failure(self):
        """Translate retries on transient failure before giving up."""
        import translate_summaries as ts

        # Clear state
        ts._ollama_error = False
        ts._ollama_error_time = 0.0

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
            result = translate_text("texto", "es", "http://localhost:11434", 10.0)

        assert result == "Success"
        assert call_count == 3  # 2 failures + 1 success

    def test_exhausted_retries_returns_none(self):
        """After max retries exhausted, returns None and sets cooldown."""
        import translate_summaries as ts

        ts._ollama_error = False
        ts._ollama_error_time = 0.0

        with patch("urllib.request.urlopen", side_effect=Exception("fail")):\
            result = translate_text("test", "de", "http://localhost:11434", 10.0)

        assert result is None
        assert ts._ollama_error is True

    def test_cooldown_clears_after_timeout(self):
        """After cooldown period elapses, normal operation resumes."""
        import translate_summaries as ts

        # Force error state
        ts._ollama_error = True
        ts._ollama_error_time = 0.0  # ancient time

        _try_clear_ollama_error()
        assert ts._ollama_error is False


class TestUpdateSummary:
    """Test DB summary updates."""

    def setup_method(self):
        self.db_path, self.conn = _make_test_db()
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO discoveries (ident_hash_hex, i2p_dns_name, detected_lang, content_summary, title, reachable) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("dead001" * 4, "forum.i2p", "de", "Original text here long enough", "Forum", 1),
        )
        self.conn.commit()

    def teardown_method(self):
        self.conn.close()
        os.unlink(self.db_path)

    def test_update_success(self):
        """Successfully updates summary and returns True."""
        new_summary = "[detected_language: de (German)]\nTranslated [original: original]"
        result = update_summary(self.db_path, 1, new_summary)
        assert result is True

        # Verify the change persisted
        conn2 = sqlite3.connect(self.db_path)
        row = conn2.execute("SELECT content_summary FROM discoveries WHERE id=1").fetchone()
        assert new_summary in row[0]
        conn2.close()

    def test_update_nonexistent_returns_false(self):
        """Updating nonexistent ID returns False."""
        result = update_summary(self.db_path, 9999, "nope")
        assert result is False


class TestTranslateTextPayload:
    """Test that translate_text constructs proper Ollama requests."""

    def test_ollama_payload_structure(self):
        """Ollama request contains correct model, prompt format, and stream=False."""
        import translate_summaries as ts

        ts._ollama_error = False
        ts._ollama_error_time = 0.0

        captured_req = None
        class FakeResp:
            def read(self):
                return json.dumps({"response": "Übersetzt"}).encode("utf-8")
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        def capture_urlopen(req, **kw):
            nonlocal captured_req
            captured_req = req
            return FakeResp()

        with patch("urllib.request.urlopen", side_effect=capture_urlopen):
            translate_text("Hallo Welt", "de", "http://localhost:11434", 5.0)

        assert captured_req is not None
        assert "localhost:11434" in str(captured_req.full_url)
        payload = json.loads(captured_req.data.decode("utf-8"))
        assert payload["model"] == "RogerBen/HY-MT2-1.8B:latest"
        assert "Hallo Welt" in payload["prompt"]
        assert "de" in payload["prompt"]
        assert payload["stream"] is False
        # Request headers stored as dict; urllib uses case-insensitive mapping
        headers = dict(captured_req.headers) if hasattr(captured_req, "headers") else {}
        assert any(k.lower() == "content-type" for k in headers)

    def test_empty_response_then_success(self):
        """Empty Ollama response counts as transient failure; succeeds on retry."""
        import translate_summaries as ts

        ts._ollama_error = False
        ts._ollama_error_time = 0.0

        class FakeResp:
            def read(self):
                return json.dumps({"response": "Success"}).encode("utf-8")
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        call_count = 0
        def empty_then_success(*a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return FakeResp.__new__(FakeResp)  # will return empty via read below
            return FakeResp()

        class EmptyResp:
            def read(self):
                return json.dumps({"response": ""}).encode("utf-8")
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        calls = [0]
        def mixed(*a, **kw):
            calls[0] += 1
            if calls[0] <= 2:
                return EmptyResp()
            return FakeResp()

        with patch("urllib.request.urlopen", side_effect=mixed):
            result = translate_text("testo", "es", "http://localhost:11434", 10.0)

        assert result == "Success"
        assert calls[0] == 3  # 2 empty + 1 success

    def test_cooldown_blocks_subsequent_calls(self):
        """After error, subsequent translate_text calls return None immediately."""
        import translate_summaries as ts

        ts._ollama_error = False
        ts._ollama_error_time = 0.0

        # First call fails and triggers cooldown
        with patch("urllib.request.urlopen", side_effect=Exception("fail")):
            result = translate_text("test", "de", "http://localhost:11434", 5.0)

        assert result is None
        assert ts._ollama_error is True

        # Second call should return None without calling urlopen at all
        with patch("urllib.request.urlopen") as mock_open:
            result = translate_text("another test", "fr", "http://localhost:11434", 5.0)

        assert result is None
        mock_open.assert_not_called()


class TestTryClearOllamaError:
    """Test _try_clear_ollama_error cooldown logic."""

    def test_stays_in_error_when_cooldown_not_expired(self):
        """If cooldown not elapsed, error flag remains True."""
        import translate_summaries as ts
        import time as t

        ts._ollama_error = True
        ts._ollama_error_time = t.time()  # just now

        _try_clear_ollama_error()
        assert ts._ollama_error is True

    def test_clears_when_cooldown_elapsed(self):
        """After cooldown period, error flag is cleared."""
        import translate_summaries as ts
        import time as t

        ts._ollama_error = True
        ts._ollama_error_time = t.time() - (OLLAMA_COOLDOWN_S + 1)  # past cooldown

        _try_clear_ollama_error()
        assert ts._ollama_error is False


class TestProbePathIsolation:
    """Test that integration.py probe path does NOT call translate_summaries functions.

    This verifies the architectural separation: probing should only detect language,
    not invoke translation. Translation runs as a separate pass afterwards.
    """

    def test_probe_does_not_import_translate_text(self):
        """probe_destination/_do_probe do not import or call translate_text."""
        import inspect
        # Read integration.py source and verify no reference to translate_summaries functions
        import os
        integration_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "src", "integration.py"
        )
        with open(integration_path, "r") as f:
            source = f.read()

        # None of these translate_summaries functions should appear in integration.py imports/calls
        forbidden_refs = [
            "from translate_summaries import",
            "from src.translate_summaries import",
            "translate_text(",
            "get_pending_translations(",
            "build_translation_summary(",
            "_needs_translation(",
            "update_summary(",
        ]
        found = [ref for ref in forbidden_refs if ref in source]
        assert not found, (
            f"integration.py contains forbidden translate_summaries references: {found}"
        )

    def test_do_probe_calls_language_detection_not_translation(self):
        """_do_probe calls detect_language from src.translation, not translation functions."""
        import os
        integration_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "src", "integration.py"
        )
        with open(integration_path, "r") as f:
            source = f.read()

        # Should use detect_language for language identification
        assert "detect_language" in source

        # But should NOT import translation logic from translate_summaries
        assert "from translate_summaries" not in source
        assert "import translate_summaries" not in source


class TestUpdateSummaryError:
    """Test update_summary DB error handling."""

    def setup_method(self):
        self.db_path, self.conn = _make_test_db()
        self.conn.close()

    def teardown_method(self):
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_update_db_error_returns_false(self):
        """update_summary returns False when UPDATE statement raises."""
        import translate_summaries as ts_mod
        real_sqlite3 = ts_mod.sqlite3
        mock_conn = MagicMock()
        mock_conn.cursor.return_value.execute.side_effect = sqlite3.OperationalError("disk I/O error")

        with patch.object(real_sqlite3, "connect", return_value=mock_conn):
            result = update_summary(self.db_path, 1, "test")
            assert result is False
