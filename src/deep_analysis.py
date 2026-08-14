"""Deep site analysis using local Ollama.

Runs as a separate step after probing. Instead of basic keyword classification,
sends page content to a local LLM for structured analysis (site type, purpose,
key sections). Results stored in discoveries.deep_analysis column.

Prompts are loaded from disk (`analysis_prompt.txt` by default) so users can
edit them without modifying Python source.  Default model HY-MT2 works within
the ~7.6GB RAM constraint but `--ollama-model` enables any model when available.

Body HTML is re-fetched via the I2P proxy at analysis time to avoid storing
megabytes of raw HTML in SQLite.
"""
from __future__ import annotations

import sys
sys.path.insert(0, ".")  # Allow 'src.*' imports when run

import argparse
import json
import logging
import os
import random
import sqlite3
import socket
import time
from html.parser import HTMLParser
from pathlib import Path
from typing import List, Optional
from urllib.error import URLError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration — override via CLI flags or environment variables
# ---------------------------------------------------------------------------

_DEFAULT_OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
_DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "RogerBen/HY-MT2-1.8B:latest")
_DEFAULT_PROMPT_PATH = str(Path(__file__).parent.parent / "analysis_prompt.txt")

_ollama_error: bool = False
_ollama_error_time: float = 0.0
# Shorter cooldown so transient failures don't block an entire batch.
# A single stalled model call shouldn't kill a 50-site run.
_OLLAMA_COOLDOWN_S: float = 60
_retry_max_attempts: int = 3
# Base delay higher than translation.py (1.0 vs 0.5) since deep analysis
# runs offline and benefits from longer pauses between slow LLM calls.
_retry_base_delay: float = 1.0

# Default timeout for Ollama generate calls (seconds). Individual calls scale
# up based on body text size in call_ollama().
_DEFAULT_OLLAMA_TIMEOUT: float = 60.0

# Timeout for fetching body via I2P proxy (generous for slow tunnels)
_I2P_FETCH_TIMEOUT = 60.0


# ---------------------------------------------------------------------------
# HTML cleanup — strip tags to body text for the prompt
# ---------------------------------------------------------------------------


class _HTMLStripper(HTMLParser):
    """Extract visible text from HTML, collapsing whitespace."""

    def __init__(self) -> None:
        super().__init__()
        self._pieces: list[str] = []
        self._skip: bool = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in ("style", "script", "noscript"):
            self._skip = True

    def handle_endtag(self, tag: str) -> None:
        if tag in ("style", "script", "noscript"):
            self._skip = False

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        cleaned = " ".join(data.split())
        if cleaned:
            self._pieces.append(cleaned)

    def text(self) -> str:
        return " ".join(self._pieces)




def _strip_markdown_fences(text: str) -> str:
    """Remove ```json ... ``` fences if the model wrapped JSON in markdown.

    Ollama small models often respond with ````json\n{...}\n```. This strips
    those fences so json.loads() can parse the inner content directly.
    """
    result = text
    if result.startswith("```"):
        result = result.split("\n", 1)[-1]
        if result.endswith("```"):
            result = result[:-3]
        result = result.strip()
    return result


def strip_html(html_text: str) -> str:
    """Remove HTML tags, keep visible text."""
    stripper = _HTMLStripper()
    stripper.feed(html_text)
    return stripper.text()[:8192]  # Sufficient context without blowing token budget


# ---------------------------------------------------------------------------
# Body fetching via I2P proxy (re-fetch at analysis time)
# ---------------------------------------------------------------------------

def get_i2p_proxy_config(db_path: str) -> tuple:
    """Get I2P proxy host and port.

    Returns (host, port) tuple using I2PConfig defaults (localhost:4444).
    Falls back to DB i2p_config table if it exists.
    """
    from src.config import I2PConfig

    # Try DB first
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT value FROM i2p_config WHERE key = 'proxy_host'")
        row = cur.fetchone()
        if row:
            cur.execute("SELECT value FROM i2p_config WHERE key = 'proxy_port'")
            port_row = cur.fetchone()
            if port_row:
                conn.close()
                return (row[0], int(port_row[0]))
        conn.close()
    except Exception:
        pass

    # Fall back to I2PConfig defaults
    cfg = I2PConfig()
    return cfg.http


def fetch_body_via_proxy(
    host: str,
    port: int,
    b32_addr: str,
    dns_name: str,
) -> Optional[str]:
    """Fetch the body of one I2P destination via the proxy client."""
    from src.i2p_proxy import fetch_i2p

    urls_to_try = []
    if dns_name:
        urls_to_try.append(f"http://{dns_name}")
    if b32_addr and len(b32_addr) >= 10:
        urls_to_try.append(f"http://{b32_addr}")

    for url in urls_to_try:
        attempt = 0
        while attempt < _retry_max_attempts:
            attempt += 1
            try:
                res = fetch_i2p(url, timeout=_I2P_FETCH_TIMEOUT)
                if res.status == 200:
                    return res.text
            except Exception as exc:
                logger.debug(f"Fetch attempt {attempt}: {exc}")
                if attempt < _retry_max_attempts:
                    time.sleep(_retry_base_delay * (2 ** (attempt - 1)))
            else:
                return None
        break
    return None


# ---------------------------------------------------------------------------
# Ollama client — reuses translation.py pattern
# ---------------------------------------------------------------------------

def _try_clear_ollama_error() -> None:
    """Clear error latch if cooldown elapsed."""
    global _ollama_error, _ollama_error_time
    if _ollama_error and time.time() - _ollama_error_time >= _OLLAMA_COOLDOWN_S:
        _ollama_error = False


def call_ollama(
    body_text: str,
    prompt_template: str,
    ollama_url: str,
    model: str,
    timeout: float = 30.0,
) -> Optional[str]:
    """Send analysis request to Ollama with retry logic.

    Returns raw response text on success, None on failure after retries.

    Timeout scales with body size — small models need more time for large prompts.
    Max timeout capped at 120s to avoid hanging indefinitely. Each 1000 chars of
    body text adds ~0.5s to the base timeout (60s default).
    """
    global _ollama_error, _ollama_error_time

    import urllib.request

    _try_clear_ollama_error()
    if _ollama_error:
        logger.warning("Ollama in cooldown — skipping")
        return None

    final_prompt = prompt_template.replace("{{BODY}}", body_text)

    # Scale timeout with prompt size: base + 0.5s per 1000 chars of body text
    effective_timeout = min(timeout + len(body_text) / 2000, 120.0)

    attempt = 0
    while attempt < _retry_max_attempts:
        attempt += 1
        try:
            payload = json.dumps({
                "model": model,
                "prompt": final_prompt,
                "stream": False,
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{ollama_url}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=effective_timeout) as resp:
                data = json.loads(resp.read())

            result = data.get("response", "").strip()
            if not result:
                continue  # empty response → retry

            return result

        except Exception as exc:
            logger.debug(f"Ollama analysis failed (attempt {attempt}): {exc}")
            if attempt < _retry_max_attempts:
                delay = _retry_base_delay * (2 ** (attempt - 1)) + random.uniform(0, 1)
                time.sleep(delay)
                continue

    # Exhausted retries — set global cooldown
    _ollama_error = True
    _ollama_error_time = time.time()
    return None


# ---------------------------------------------------------------------------
# DB helpers for pending analysis queries
# ---------------------------------------------------------------------------

def get_pending_analyses(
    db_path: str,
    mode: str = "reachable",
    limit: int = 50,
) -> List[tuple]:
    """Return targets pending deep analysis.

    Args:
        db_path: Path to indexer.db (or any SQLite DB with discoveries/targets tables)
        mode: 'reachable' (all reachable sites), 'stale' (not analyzed or >30d old),
              'never_analyzed' (deep_analysis is empty)
        limit: Max rows to return

    Returns:
        List of (ident_hash_hex, b32_addr, i2p_dns_name) tuples.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    if mode == "reachable":
        # All reachable sites, prioritize never analyzed first, then oldest probes
        query = """
            SELECT d.ident_hash_hex, d.b32_addr, d.i2p_dns_name
            FROM (
                SELECT DISTINCT d.ident_hash_hex, d.b32_addr, d.i2p_dns_name
                FROM discoveries d
                WHERE d.reachable = 1
                  AND (d.title IS NOT NULL OR LENGTH(d.content_summary) > 0)
                ORDER BY
                    CASE WHEN LENGTH(COALESCE(d.deep_analysis, '')) = 0 THEN 0 ELSE 1 END,
                    d.probed_at DESC
                LIMIT ?
            ) d
        """
    elif mode == "stale":
        # Sites not analyzed or analysis older than 30 days (2592000 seconds)
        query = """
            SELECT d.ident_hash_hex, d.b32_addr, d.i2p_dns_name
            FROM (
                SELECT DISTINCT d.ident_hash_hex, d.b32_addr, d.i2p_dns_name
                FROM discoveries d
                LEFT JOIN targets t ON d.ident_hash_hex = t.ident_hash_hex
                WHERE d.reachable = 1
                  AND (t.last_analyzed_at IS NULL OR t.last_analyzed_at = 0
                       OR t.last_analyzed_at < strftime('%s','now') - 2592000)
                ORDER BY COALESCE(t.last_analyzed_at, 0) ASC, d.probed_at DESC
                LIMIT ?
            ) d
        """
    elif mode == "never_analyzed":
        # Only sites with no analysis yet
        query = """
            SELECT d.ident_hash_hex, d.b32_addr, d.i2p_dns_name
            FROM (
                SELECT DISTINCT d.ident_hash_hex, d.b32_addr, d.i2p_dns_name
                FROM discoveries d
                WHERE d.reachable = 1
                  AND (d.deep_analysis IS NULL OR LENGTH(d.deep_analysis) = 0)
              ORDER BY d.probed_at DESC
                LIMIT ?
            ) d
        """
    else:
        raise ValueError(f"Unknown mode: {mode}")

    cur.execute(query, (limit,))
    results = cur.fetchall()
    conn.close()
    return results


def update_analysis(
    db_path: str,
    ident_hash_hex: str,
    probe_mode: str,
    analysis_json: str,
) -> None:
    """Store deep analysis result in the discoveries table via UPDATE.

    Updates any qualifying discovery row for this destination (all probe modes).
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    try:
        query = """
            UPDATE discoveries
            SET deep_analysis = ?
            WHERE ident_hash_hex = ?
              AND (deep_analysis IS NULL OR LENGTH(deep_analysis) = 0)
        """
        cur.execute(query, (analysis_json, ident_hash_hex))

        # Update last_analyzed_at on targets for tracking
        if ident_hash_hex and len(ident_hash_hex) >= 10:
            cur.execute(
                "UPDATE targets SET last_analyzed_at = strftime('%s','now') "
                "WHERE ident_hash_hex = ?",
                (ident_hash_hex,),
            )

        conn.commit()
    except Exception as e:
        logger.error(f"Failed to store analysis for {ident_hash_hex}: {e}")
        conn.rollback()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# CLI argparse — main entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deep site analysis using local Ollama"
    )
    parser.add_argument(
        "--db", default=None,
        help="Path to indexer.db (default: ./indexer.db)",
    )
    parser.add_argument(
        "--mode", choices=["reachable", "stale", "never_analyzed"],
        default="reachable",
        help="Selection mode for sites to analyze (default: reachable)",
    )
    parser.add_argument(
        "--limit", type=int, default=50,
        help="Max sites to process per run (default: 50)",
    )
    parser.add_argument(
        "--ollama-url", default=_DEFAULT_OLLAMA_URL,
        help=f"Ollama endpoint URL (default: {_DEFAULT_OLLAMA_URL})",
    )
    parser.add_argument(
        "--ollama-model", default=_DEFAULT_MODEL,
        help=f"Model name (default: {_DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--timeout", type=float, default=_DEFAULT_OLLAMA_TIMEOUT,
        help=f"Ollama call timeout in seconds. Scales with body size (max 120s). "
             f"(default: {_DEFAULT_OLLAMA_TIMEOUT})",
    )
    parser.add_argument(
        "--prompt", default=_DEFAULT_PROMPT_PATH,
        help=f"Path to prompt template file (default: {_DEFAULT_PROMPT_PATH})",
    )
    return parser.parse_args()


def main() -> None:
    """CLI entry point for deep analysis."""
    import sys

    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # Find DB
    db_path = args.db or "indexer.db"
    if not Path(db_path).exists():
        logger.error(f"Database not found: {db_path}")
        sys.exit(1)

    # Load prompt template
    try:
        with open(args.prompt, "r", encoding="utf-8") as f:
            prompt_template = f.read()
        logger.info(f"Loaded prompt from {args.prompt} ({len(prompt_template)} chars)")
    except FileNotFoundError:
        logger.error(f"Prompt file not found: {args.prompt}")
        sys.exit(1)

    # Get I2P proxy config (always available via I2PConfig defaults)
    proxy_cfg = get_i2p_proxy_config(db_path)
    host, port = proxy_cfg
    logger.info(f"Using I2P proxy: {host}:{port}")

    # Get pending analyses
    try:
        pending = get_pending_analyses(db_path, mode=args.mode, limit=args.limit)
        logger.info(f"Found {len(pending)} sites pending analysis")
    except Exception as e:
        logger.error(f"Failed to query database: {e}")
        sys.exit(1)

    if not pending:
        logger.info("No sites need analysis")
        return

    # Process each site
    processed = 0
    failed = 0
    for i, row in enumerate(pending, 1):
        ident_hash, b32_addr, dns_name = row
        label = dns_name or b32_addr[:40]

        # Fetch body via proxy
        body_html = fetch_body_via_proxy(host, port, b32_addr, dns_name)

        if not body_html or len(body_html) < 100:
            logger.debug(f"[{i}/{len(pending)}] SKIP {label} — no/insufficient body")
            continue

        # Strip HTML to get body text for the prompt
        body_text = strip_html(body_html)

        # Call Ollama
        result = call_ollama(
            body_text=body_text,
            prompt_template=prompt_template,
            ollama_url=args.ollama_url,
            model=args.ollama_model,
            timeout=args.timeout,
        )

        if result:
            # Determine probe_mode from b32 vs dns name
            probe_mode = "b32" if len(b32_addr) > 40 else "dns"

            # Try to parse JSON from the response
            try:
                result_text = _strip_markdown_fences(result)
                analysis_obj = json.loads(result_text)
                analysis_json = json.dumps(analysis_obj)
            except json.JSONDecodeError:
                # If not valid JSON, wrap the raw text
                analysis_json = json.dumps({"raw_analysis": result})

            update_analysis(db_path, ident_hash, probe_mode, analysis_json)
            processed += 1
            logger.info(f"[{i}/{len(pending)}] ✓ Analyzed {label} ({ident_hash[:8]}...)")
        else:
            failed += 1
            logger.warning(f"[{i}/{len(pending)}] ✗ Failed to analyze {label}")

    logger.info(
        f"Done: {processed} analyzed, {failed} failed out of "
        f"{len(pending)} sites"
    )


if __name__ == "__main__":
    main()
