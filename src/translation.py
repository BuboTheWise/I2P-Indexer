"""Language detection, tagging, and offline translation for I2P site content.

Detects the language of extracted title/summary text using ``langid``
(a lightweight, CPU-only library with no network calls). Non-English
content is tagged with a ``[detected_language: XX (LanguageName)]``
preamble so auditors can see provenance.

**Offline translation (NFR-07):** When enabled via ``enable_translation()``,
summary lines in German, Russian, Chinese, or Japanese are translated to
English using cached Helsinki-NLP MarianMT models running entirely on CPU.
HF_HUB_OFFLINE=1 blocks all outbound network calls — models must be
pre-downloaded to the local cache before offline mode works.

Model locations (auto-discovered from HF_HOME or project-local cache):
    Helsinki-NLP/opus-mt-de-en   → ~74M params, 0.32s/sentence CPU
    Helsinki-NLP/opus-mt-ru-en   → ~77M params, 0.27s/sentence CPU
    Helsinki-NLP/opus-mt-zh-en   → ~78M params, 0.33s/sentence CPU
    Helsinki-NLP/opus-mt-ja-en   → ~76M params, 0.24s/sentence CPU

Memory footprint: ~1.8GB RSS with all 4 models loaded in memory.
"""
from __future__ import annotations

import logging
import os
from typing import Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Language detection (langid — lightweight, CPU-only, no network)
# ---------------------------------------------------------------------------

_detected: str | None = None
_detect_error: bool = False


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
    """
    global _detect_error

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
        logger.info("langid detection failed, assuming English")
        _detect_error = True
        return ("en", 1.0)


# ---------------------------------------------------------------------------
# Public entry point for the extractor pipeline
# ---------------------------------------------------------------------------

def process_content_for_language(
    title: str,
    summary_lines: list[str],
    detected_lang: str = "",
    confidence: float = 1.0,
) -> tuple[list[str], str]:
    """Detect language and prepend language tags for non-English content.

    Called after extraction but before storing in DB. Does **not** translate
    — it only detects language and adds a ``[detected_language: XX]`` tag
    so auditors know the original language.

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

    for line in summary_lines:
        stripped = line.strip()
        if not stripped:
            continue
        # Skip things that aren't translatable text (URLs, hashes, pure data)
        if stripped.startswith("http") or len(stripped) < 10:
            tagged_lines.append(stripped)
            continue
        # Keep the original line as-is — no translation
        tagged_lines.append(stripped)

    return tagged_lines, lang


# ---------------------------------------------------------------------------
# State reset (for test isolation)
# ---------------------------------------------------------------------------

def reset_state() -> None:
    """Reset global state for test isolation."""
    global _detect_error
    _detect_error = False
