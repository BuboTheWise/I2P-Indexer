#!/usr/bin/env python3
"""Standalone translation pass for non-English I2P site summaries.

Separates translation concerns from the probe sweep so they can be managed
independently.  Finds reachable discoveries with non-English detected_lang
whose content_summary has not yet been translated and sends them through
a local Ollama endpoint for English translation.

Usage:
    python3 translate_summaries.py --ollama-url http://localhost:11434
    python3 translate_summaries.py --ollama-url http://localhost:11434 --dry-run --limit 50
    python3 translate_summaries.py --lang ru              # only Russian sites

--- How it works ---

For each matching discovery:
    1. Extract the original (non-English) summary text from content_summary.
       If a translation already exists (``[lang]: ... [original: ...]`` pattern),
       skip — we never overwrite an existing translation.
    2. Send the text to Ollama's /api/generate endpoint with HY-MT2 model.
    3. On success, update content_summary in place: prepend ``[lang]: `` prefix
       and append ``[original: …]`` to the first content line that was translated.
    4. Upsert back into discoveries table (same conflict key).

Options:
    --ollama-url      Ollama API endpoint (required)
    --lang            Only translate this language code (ISO 639-1)
    --limit           Max number of sites to process (default=all pending)
    --dry-run         Show what would be translated without actually doing it
    --timeout         Per-request Ollama timeout in seconds (default 30)
"""
import argparse
import json
import logging
import os
import random
import sqlite3
import sys
import time
import urllib.request
from datetime import datetime, timezone

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ".")

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "indexer.db")
OLLAMA_MODEL = "RogerBen/HY-MT2-1.8B:latest"
MAX_TOKENS = 4096  # summary max length

_LANG_NAMES = {
    "de": "German", "fr": "French", "es": "Spanish", "ja": "Japanese",
    "zh": "Chinese", "ru": "Russian", "pt": "Portuguese", "it": "Italian",
    "ko": "Korean", "ar": "Arabic", "nl": "Dutch", "sv": "Swedish",
    "no": "Norwegian", "da": "Danish", "fi": "Finnish", "pl": "Polish",
    "cs": "Czech", "hu": "Hungarian", "ro": "Romanian", "tr": "Turkish",
    "el": "Greek", "he": "Hebrew", "th": "Thai", "vi": "Vietnamese",
    "id": "Indonesian", "ms": "Malay", "hi": "Hindi", "uk": "Ukrainian",
    "ky": "Kyrgyz", "la": "Latin", "rw": "Kinyarwanda", "km": "Khmer",
    "be": "Belarusian", "bg": "Bulgarian", "sw": "Swahili", "mt": "Maltese",
}

# ---------------------------------------------------------------------------
# Ollama client — per-request retry with bounded backoff
# ---------------------------------------------------------------------------

_ollama_error = False        # legacy global cooldown flag (kept for compat)
_ollama_error_time = 0.0
OLLAMA_COOLDOWN_S = 300      # default 5 minutes before retry (overridable via --cooldown)

# Per-request retry config — prevents single timeout from blocking entire batch
_retry_max_attempts = 3
_retry_base_delay = 2.0


def _try_clear_ollama_error() -> None:
    global _ollama_error, _ollama_error_time
    if _ollama_error and time.time() - _ollama_error_time >= OLLAMA_COOLDOWN_S:
        _ollama_error = False


def translate_text(text: str, source_lang: str, url: str, timeout: float) -> str | None:
    """Translate *text* from *source_lang* to English via Ollama.

    Retries up to _retry_max_attempts with exponential backoff on transient failures.
    Returns translated string or None on failure.
    """
    global _ollama_error, _ollama_error_time

    if not url:
        return None

    _try_clear_ollama_error()
    if _ollama_error:
        logger.debug("Ollama in cooldown — skipping")
        return None

    if source_lang == "en":
        return text

    attempt = 0
    while attempt < _retry_max_attempts:
        attempt += 1
        try:
            payload = json.dumps({
                "model": OLLAMA_MODEL,
                "prompt": f"Translate the following {source_lang} text to English. Output only the translation, nothing else:\n{text}",
                "stream": False,
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{url}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())

            result = data.get("response", "").strip()
            if not result:
                continue  # empty response counts as transient failure

            # Sanity: multi-paragraph response → truncate to first paragraph
            if "\n" in result and len(result.split("\n")) > 3:
                result = result.split("\n")[0].strip()

            return result

        except Exception as exc:
            logger.debug(f"Ollama translation failed (attempt {attempt}): {exc}")
            if attempt < _retry_max_attempts:
                delay = _retry_base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)
                logger.debug(f"Retrying in {delay:.1f}s")
                time.sleep(delay)
                continue

    # Exhausted retries
    _ollama_error = True
    _ollama_error_time = time.time()
    return None


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def get_pending_translations(db_path: str, lang_filter: str = "", limit: int = 0) -> list[dict]:
    """Fetch reachable discoveries that need translation.

    A discovery needs translation if:
    - reachable = 1
    - detected_lang is set and != 'en'
    - content_summary does NOT already contain a translation pattern
      (detected_language tag OR [lang: prefix)
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    where = "reachable=1 AND detected_lang != '' AND detected_lang != 'en'"
    params: list = []

    # Skip already-translated entries (translator adds [original: tag)
    # Do NOT filter [detected_language:] here: probe adds that tag before Ollama runs,
    # so filtering it would block all untranslated entries from being fetched.
    where += " AND content_summary NOT LIKE '%[original:%'"

    if lang_filter:
        where += " AND detected_lang = ?"
        params.append(lang_filter)

    if limit:
        where += f" LIMIT {int(limit)}"

    cur.execute(f"SELECT id, ident_hash_hex, i2p_dns_name, detected_lang, content_summary, title FROM discoveries WHERE {where}", params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def update_summary(db_path: str, discovery_id: int, new_summary: str) -> bool:
    """Update content_summary for a single discovery by ID."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE discoveries SET content_summary=? WHERE id=?",
            (new_summary, discovery_id),
        )
        conn.commit()
        changed = cur.rowcount > 0
        return changed
    except Exception as e:
        logger.error(f"Failed to update discovery {discovery_id}: {e}")
        return False
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Translation logic
# ---------------------------------------------------------------------------

def _needs_translation(summary: str) -> bool:
    """Check if a summary already has a translation applied."""
    if not summary or len(summary.strip()) < 10:
        return False
    # Already translated — probe adds [detected_language:], translator adds [original: ..]
    if "[original:" in summary:
        return False
    return True


def build_translation_summary(original_summary: str, translated_line: str, source_lang: str) -> str:
    """Build new content_summary with translation prepended.

    Format:
        [detected_language: de (German)]
        <translated_first_line> [original: <original_first_line>]
        <remaining_original_lines...>
    """
    lang_name = _LANG_NAMES.get(source_lang, "")
    preamble = f"[detected_language: {source_lang}{f' ({lang_name})' if lang_name else ''}]"

    lines = original_summary.split("\n")
    content_lines = [l.strip() for l in lines if l.strip()]

    if not content_lines:
        return original_summary

    # Skip URLs / short lines that aren't translatable
    first_translatable = None
    idx = 0
    for i, line in enumerate(content_lines):
        if line.startswith("http") or len(line) < 10:
            continue
        first_translatable = i
        idx = i
        break

    if first_translatable is None:
        # Nothing to translate — just tag it
        tagged_lines = [preamble] + content_lines
        return "\n".join(tagged_lines)

    original_first = content_lines[first_translatable]

    new_lines = [preamble, f"{translated_line} [original: {original_first}]"]
    # Add remaining lines (skipping the one we already translated)
    for j, line in enumerate(content_lines):
        if j == first_translatable:
            continue
        new_lines.append(line)

    return "\n".join(new_lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global OLLAMA_COOLDOWN_S

    p = argparse.ArgumentParser(description="Translate non-English I2P site summaries via local Ollama")
    p.add_argument("--ollama-url", required=True, help="Ollama API endpoint (e.g. http://localhost:11434)")
    p.add_argument("--lang", default="", help="Only translate this language code (ISO 639-1)")
    p.add_argument("--limit", type=int, default=0, help="Max sites to process (0=all)")
    p.add_argument("--dry-run", action="store_true", help="Show what would be translated without doing it")
    p.add_argument("--timeout", type=float, default=30.0, help="Per-request Ollama timeout in seconds")
    p.add_argument("--cooldown", type=float, default=OLLAMA_COOLDOWN_S, help="Cooldown after Ollama error (seconds)")
    p.add_argument("--db-path", default=None, dest="db_path", help="Path to indexer.db")

    args = p.parse_args()
    db_path = args.db_path or DEFAULT_DB_PATH

    if not os.path.exists(db_path):
        print(f"Error: database not found at {db_path}")
        sys.exit(1)

    OLLAMA_COOLDOWN_S = args.cooldown

    # Check Ollama connectivity upfront
    try:
        req = urllib.request.Request(f"{args.ollama_url}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            models = json.loads(resp.read())
            model_names = [m["name"] for m in models.get("models", [])]
            print(f"Ollama connected — {len(model_names)} model(s) available")
            if OLLAMA_MODEL not in str(model_names):
                print(f"  WARNING: {OLLAMA_MODEL} not found. Available: {', '.join(model_names[:5])}")
    except Exception as e:
        print(f"Error: Cannot reach Ollama at {args.ollama_url}: {e}")
        sys.exit(1)

    # Fetch pending translations
    lang_info = f" (lang={args.lang})" if args.lang else ""
    pending = get_pending_translations(db_path, lang_filter=args.lang, limit=args.limit)
    print(f"\nFound {len(pending)} discoveries needing translation{lang_info}")

    if not pending:
        print("Nothing to do.")
        return

    translated = 0
    skipped = 0
    failed = 0
    start = time.time()

    for entry in pending:
        didl = entry["i2p_dns_name"] or entry["ident_hash_hex"][:12]
        lang = entry["detected_lang"]
        summary = entry.get("content_summary", "")

        if not _needs_translation(summary):
            skipped += 1
            continue

        original_text = "\n".join(
            line.strip() for line in summary.split("\n")
            if line.strip() and not line.startswith("http") and len(line.strip()) >= 10
        )

        if not original_text:
            skipped += 1
            continue

        if args.dry_run:
            print(f"  [DRY] Would translate [{lang}] {didl}: {original_text[:80]}...")
            translated += 1
            continue

        result = translate_text(original_text, lang, args.ollama_url, args.timeout)
        if not result:
            failed += 1
            print(f"  [FAIL] [{lang}] {didl} — translation failed")
            continue

        new_summary = build_translation_summary(summary, result, lang)
        if update_summary(db_path, entry["id"], new_summary):
            translated += 1
            print(f"  [OK]   [{lang}] {didl}")
        else:
            failed += 1

    elapsed = time.time() - start
    print(f"\nDone in {elapsed:.1f}s: {translated} translated, {skipped} skipped, {failed} failed")


if __name__ == "__main__":
    main()
