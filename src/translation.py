"""Language detection, tagging, and local translation for I2P site content.

Detects the language of extracted title/summary text using ``langid``
(a lightweight, CPU-only library with no network calls). Non-English
content is tagged with a ``[detected_language: XX (LanguageName)]``
preamble so auditors can see provenance.

**Local translation:** When an Ollama endpoint is configured via
``I2PConfig.ollama_url``, summary lines in non-English languages are
translated to English using the HY-MT2 multilingual model over the
Ollama API (localhost by default). Falls back gracefully when Ollama
is unavailable — probes never fail due to translation errors.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Language detection (langid — lightweight, CPU-only, no network)
# ---------------------------------------------------------------------------

_detected: str | None = None
_detect_error: bool = False
_detect_error_time: float = 0.0
_DETECT_COOLDOWN_S: float = 60.0  # reset error latch after 60s


def _detect_langid(text: str) -> Tuple[str, float]:
    """Detect language using the langid library.

    Returns ``(iso_code, confidence)`` where ``iso_code`` is an ISO 639-1
    code (e.g. ``'en'``, ``'de'``, ``'ja'``) and confidence is a raw
    score from the underlying model.\n    Raises an exception on failure, which the caller catches.
    """
    import langid  # type: ignore[import-untyped]

    code, score = langid.classify(text)
    return code.split("_")[0], score


def detect_language(
    title: str,
    body_text: str,
    min_confidence: float = 0.4,
) -> Tuple[str, float]:
    """Detect the language of page content.

    Combines ``title`` and a sample of ``body_text`` for better accuracy.
    Returns ``(lang_code, confidence)``. Confidence is normalised to
    0.0-1.0; values below ``min_confidence`` cause us to fall back to
    ``'en'`` to avoid noisy detection on sparse content.

    On failure (library unavailable, empty text) returns ``('en', 1.0)``
    so the sweeper never hangs — it just treats everything as English.

    Transient errors auto-reset after _DETECT_COOLDOWN_S so a single
    langid glitch doesn't poison the entire probe run forever.
    """
    global _detect_error, _detect_error_time

    # Auto-clear stale error latch
    if _detect_error and time.time() - _detect_error_time >= _DETECT_COOLDOWN_S:
        _detect_error = False

    if _detect_error:
        return ("en", 1.0)

    combined = f"{title} {body_text[:8192]}"
    combined = " ".join(combined.split())
    # Skip detection on very short or pure-URL text that would be unreliable
    if len(combined) < 30:
        return ("en", 1.0)

    try:
        code, score = _detect_langid(combined)
        # langid returns negative log-probability scores. Lower (more negative)
        # means more confident. We use the raw score as-is; a threshold of -100
        # is reasonable for most real text blocks.
        conf = float(score)
        if conf <= -50:
            return (code, 1.0)  # high confidence
        # Medium confidence
        if conf <= -20:
            return (code, 0.7)
        # Low confidence → assume English to be safe
        return ("en", min(0.4, max(0.1, -conf / 100)))
    except Exception:
        logger.debug("langid detection failed once, will retry after cooldown")
        _detect_error = True
        _detect_error_time = time.time()
        return ("en", 1.0)


# ---------------------------------------------------------------------------
# Public entry point for the extractor pipeline
# ---------------------------------------------------------------------------

_OLLAMA_URL: Optional[str] = None
_OLLAMA_MODEL: str = "RogerBen/HY-MT2-1.8B:latest"
_ollama_error: bool = False
_ollama_error_time: float = 0.0
_OLLAMA_COOLDOWN_S: float = 300
_retry_max_attempts: int = 3
_retry_base_delay: float = 0.5


def set_ollama_url(url: Optional[str]) -> None:
    """Configure the Ollama endpoint for local translation."""
    global _OLLAMA_URL, _ollama_error, _ollama_error_time
    _OLLAMA_URL = url
    _ollama_error = False
    _ollama_error_time = 0.0


def _try_clear_ollama_error() -> None:
    """Clear error latch if cooldown elapsed."""
    global _ollama_error, _ollama_error_time
    if _ollama_error and time.time() - _ollama_error_time >= _OLLAMA_COOLDOWN_S:
        _ollama_error = False


def translate_to_english(
    text: str,
    source_lang: str,
    timeout: float = 30.0,
) -> Optional[str]:
    """Translate *text* from *source_lang* to English via local Ollama.

    Retries up to _retry_max_attempts with exponential backoff on transient
    failures. Returns the translated string on success, or ``None`` if Ollama
    is unavailable, times out, or returns an error after all retries.
    """
    global _ollama_error, _ollama_error_time

    if not _OLLAMA_URL:
        return None

    _try_clear_ollama_error()
    if _ollama_error:
        logger.debug("Ollama in cooldown — skipping")
        return None

    if source_lang == "en":
        return text

    import random

    attempt = 0
    while attempt < _retry_max_attempts:
        attempt += 1
        try:
            import urllib.request

            payload = json.dumps({
                "model": _OLLAMA_MODEL,
                "prompt": f"Translate the following {source_lang} text to English. Output only the translation, nothing else:\n{text}",
                "stream": False,
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{_OLLAMA_URL}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())

            result = data.get("response", "").strip()
            if not result:
                continue   # empty response → retry

            # Sanity: response contains a newline + extra text → likely not a
            # clean translation. Truncate to first paragraph in that case.
            if "\n" in result and len(result.split("\n")) > 3:
                result = result.split("\n")[0].strip()

            return result

        except Exception as exc:
            logger.debug(f"Ollama translation failed (attempt {attempt}): {exc}")
            if attempt < _retry_max_attempts:
                delay = _retry_base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)
                time.sleep(delay)
                continue

    # Exhausted retries — set global cooldown
    _ollama_error = True
    _ollama_error_time = time.time()
    return None


def process_content_for_language(
    title: str,
    summary_lines: list[str],
    detected_lang: str = "",
    confidence: float = 1.0,
) -> tuple[list[str], str]:
    """Detect language, prepend tags, and translate non-English content.

    Called after extraction but before storing in DB. When Ollama is
    configured via ``set_ollama_url()``, summary lines are translated to
    English with the original preserved as a comment.  Falls back to
    tagging-only when Ollama is unavailable.

    Returns ``(tagged_summary_lines, language_code)``. The returned
    list includes a preamble like ``"[detected_language: de (German)]"``
    when the content is non-English, so humans auditing the address book
    can see that this wasn't native English content.
    """
    if detected_lang and detected_lang != "en":
        lang = detected_lang
    else:
        # We haven't detected yet — do it now
        combined_summary = "\n".join(summary_lines)
        lang, conf = detect_language(title, combined_summary)

    if not summary_lines or lang == "en":
        return summary_lines, "en"

    # Build language label (ISO code + English name via langname mapping)
    _LANG_NAMES = {
        "de": "German", "fr": "French", "es": "Spanish", "ja": "Japanese",
        "zh": "Chinese", "ru": "Russian", "pt": "Portuguese", "it": "Italian",
        "ko": "Korean", "ar": "Arabic", "nl": "Dutch", "sv": "Swedish",
        "no": "Norwegian", "da": "Danish", "fi": "Finnish", "pl": "Polish",
        "cs": "Czech", "hu": "Hungarian", "ro": "Romanian", "tr": "Turkish",
        "el": "Greek", "he": "Hebrew", "th": "Thai", "vi": "Vietnamese",
        "id": "Indonesian", "ms": "Malay", "hi": "Hindi", "uk": "Ukrainian",
    }
    lang_name = _LANG_NAMES.get(lang, "")

    preamble = f"[detected_language: {lang}{f' ({lang_name})' if lang_name else ''}]"
    tagged_lines: list[str] = []
    tagged_lines.append(preamble)

    try:
        translated = translate_to_english("\n".join(line.strip() for line in summary_lines if line.strip()), lang)
    except Exception:
        translated = None

    first_translated = False
    for line in summary_lines:
        stripped = line.strip()
        if not stripped:
            continue
        # Skip things that aren't translatable text (URLs, hashes, pure data)
        if stripped.startswith("http") or len(stripped) < 10:
            tagged_lines.append(stripped)
            continue

        # Append translation only on the first content line, with original preserved
        if translated and not first_translated:
            tagged_lines.append(f"{translated} [original: {stripped}]")
            first_translated = True
        else:
            tagged_lines.append(stripped)

    return tagged_lines, lang


def reset_state() -> None:
    """Reset global state for test isolation."""
    global _detect_error, _ollama_error, _ollama_error_time
    _detect_error = False
    _detect_error_time = 0.0
    _ollama_error = False
    _ollama_error_time = 0.0


# ---------------------------------------------------------------------------
# Ollama probe (optional)
# ---------------------------------------------------------------------------

def _probe_ollama(url: str) -> bool:
    """Return True if an Ollama instance responds at *url*."""
    import urllib.request as _urllib

    # Derive /api/tags endpoint from the configured URL.
    base = url.replace("/api/generate", "").rstrip("/")
    tags_url = base + "/api/tags"

    try:
        req = _urllib.Request(tags_url, method="GET")
        with _urllib.urlopen(req, timeout=3) as r:
            data = r.read()
            return isinstance(data, bytes) and len(data) > 0
    except Exception:
        return False
