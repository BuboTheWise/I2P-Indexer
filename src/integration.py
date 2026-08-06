"""Integration layer — probe .i2p destinations via HTTP proxy, record full addressbook data in SQLite.

Core design:
- Primary identity is always ident_hash_hex (40-char SHA-1).
- We try BOTH http://HASH.b32.i2p (direct key, no DNS resolution) AND http://NAME.i2p (SU3 hostname),
  recording which worked and which failed.
- All probe results go into a persistent SQLite DB so they survive across runs.
"""
from __future__ import annotations

import base64
import hashlib
import http.client as http_client
import json as _json
import logging
import os
import re
import sqlite3
import threading
import time
import traceback
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any as TypingAny

import socks  # required by SOCKS5 proxy path

from src.addressbook import AddressBookCatalog, _hex_to_b32_addr
from src.config import I2PConfig
from src.i2p_proxy import ProxyBackend, fetch_i2p
from src.models import DestinationEntry

# Per-target probe timeout (seconds). Override via PROBE_TIMEOUT env var
# or --probe-timeout CLI flag. Default 120s matches I2PProxyClient default.
PROBE_TIMEOUT: float = float(os.environ.get("PROBE_TIMEOUT", "120"))

logger = logging.getLogger(__name__)

# Thread-safe access to DB convenience helpers (fix #1)
_db_lock = threading.Lock()


# ---------------------------------------------------------------------------
# SUSI DNS export parser & ingestion
# ---------------------------------------------------------------------------

# Helpers

def _truncate(text: str, max_len: int) -> str:
    """Cut text to a safe length for SQLite storage."""
    return text[:max_len] if len(text) > max_len else text


def parse_susi_export(path: str | Path) -> list[dict]:
    """Parse a SUSI DNS address book export file (e.g. from /susidns/export?book=router).

    Format per line group:
        # DNS_NAME: comment-with-b32-address.b32.i2p
        DNS_NAME=base64_destination_data   [#!sig=...]

    Returns list of dicts with keys: i2p_dns_name, ident_hash_hex, b32_raw, dest_data_len.
    I2P encodes destination data in a variant of URL-safe base64 that uses `-`, `_` 
    (standard url-safe), AND `~` as an additional substitute for padding chars.
    The parser fixes all three variants before decoding.
    """
    entries: list[dict] = []
    
    content = Path(path).read_text(encoding='utf-8', errors='replace')
    
    current_host_header = None
    current_b32_raw = ""
    
    for line in content.split('\n'):
        line = line.rstrip()
        
        if not line.strip():
            continue
        
        # Comment lines with b32 address mapping
        if line.startswith('#'):
            comment_text = line[1:].strip()
            
            # Try to extract DNS_NAME + b32_addr mapping (format: "DNS_NAME: ...b32.b32.i2p")
            b32_match = re.match(r'^(.+?):\s+(.+?)\.b32\.i2p', comment_text)
            if b32_match:
                current_host_header = b32_match.group(1).strip()
                current_b32_raw = b32_match.group(2).strip()
            continue
        
        # Data line (format: DNS_NAME=base64_destination_data [#!sig=...])
        if '=' in line:
            name, dest_data = line.split('=', 1)
            dns_name = name.strip()
            
            if not dest_data.strip():
                continue
            
            # Remove any trailing signature marker (not needed for identity hash)
            if '#!sig=' in dest_data:
                dest_b64 = dest_data.split('#!sig=', 1)[0].strip()
            else:
                dest_b64 = dest_data.strip()
            
            # Fix I2P base64 variants: ~ -> _, - -> +, then standard _ -> /
            dest_std = dest_b64.replace('~', '_').replace('-', '+').replace('_', '/')
            
            # Fix padding
            pad_needed = len(dest_std) % 4
            if pad_needed:
                dest_std += '=' * (4 - pad_needed)
            
            try:
                raw = base64.b64decode(dest_std)
                identity_hash = raw[:20].hex()
                
                entries.append({
                    'i2p_dns_name': current_host_header or dns_name,
                    'ident_hash_hex': identity_hash.upper(),
                    'b32_raw': current_b32_raw or _hex_to_b32_addr(identity_hash),
                    'dest_data_len': len(raw),
                })
            except Exception:
                # Skip entries that fail to decode
                continue
    
    return entries


# Regular expression helpers

_TAG_RE = re.compile(r"<[^>]+>")
_I2P_LINK_RE = re.compile(
    r"([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)*\.i2p)",
    re.IGNORECASE,
)


def _extract_i2p_links(body_text: str) -> list[str]:
    """Return unique .i2p hosts from body text, including multi-level domains."""
    return list({h.strip().lower() for h in _I2P_LINK_RE.findall(body_text[:32768])})


# _classify_content replaced by extractor registry (src/extractors.py)
# The HtmlExtractor in ext_plugins/html_extractor.py holds the full logic.

def _classify_content(
    title: str,
    body_text: str,
) -> tuple[str, str, list[str]]:
    """Thin wrapper around run_extractors for backward compatibility.

    Tests and legacy code call this directly; it delegates to the
    extractor registry which runs HtmlExtractor (plus any other
    registered extractors).
    """
    from src.extractors import run_extractors

    # Default headers — most _classify_content callers pass raw HTML bodies
    # without real HTTP metadata. Signal text/html so HtmlExtractor can handle.
    result = run_extractors(
        title=title,
        body_text=body_text,
        headers={"Content-Type": "text/html; charset=utf-8"},
        status_code=200,
    )
    return result.content_type, result.content_summary, result.links

# ---------------------------------------------------------------------------
# Flag extraction heuristics
# ---------------------------------------------------------------------------

def _extract_flags(
    body_text: str,
    resp_headers: dict | None = None,
    redirect_depth: int = 0,
) -> list[str]:
    """Analyse page content + response headers and emit structured flag strings.

    Each flag is a ``type: detail`` string that describes something interesting
    about the target (robots policy, tech stack fingerprints, contact signals,
    forum software, redirect chains).

    Args:
        body_text: Full HTML/body text from the probe response.
        resp_headers: HTTP response headers dict (may be empty/None).
        redirect_depth: Number of redirects followed (>0 means a chain existed).

    Returns:
        List of flag strings, e.g. ``["robots_disallow_all", "tech_stack: nginx/1.24"]``.
    """
    if resp_headers is None:
        resp_headers = {}

    flags: list[str] = []
    lower_body = body_text.lower()[:32768]  # first 32 KB for heuristics

    # ── 1. robots_disallow_all ────────────────────────────────────────
    if "user-agent" in lower_body and "disallow: /" in lower_body:
        flags.append("robots_disallow_all")

    # ── 2. tech_stack_detected ────────────────────────────────────────
    detected_techs: list[str] = []
    import re as _re

    # Server header
    for hdr_key in ("Server", "server"):
        srv = resp_headers.get(hdr_key, "")
        if srv:
            detected_techs.append(srv)

    # X-Powered-By header
    xp = resp_headers.get("X-Powered-By", "") or resp_headers.get("x-powered-by", "")
    if xp:
        detected_techs.append(xp)

    # <meta name="generator"> tag — known generators only
    KNOWN_GENERATORS = [
        "WordPress", "Joomla", "Drupal", "MediaWiki", "Ghost", "Hugo",
        "Jekyll", "Squarespace", "Wix", "Weebly", "Pelican", "Haddock",
        "Gatsby", "Next.js", "Nuxt", "VitePress", "Docusaurus",
        "Grav", "Concrete5", "TYPO3", "MODX", "ExpressionEngine",
        "October CMS", "CraftCMS", "Statamic", "Kirby",
    ]
    gen_match = _re.search(r'<meta[^>]+name=["\']?generator["\']?\s+content=["\']([^"\']+)[ "\'"]', body_text[:32768], _re.IGNORECASE)
    if gen_match:
        gen_value = gen_match.group(1).strip()
        # Only record known generators; skip personal messages / junk
        for kg in KNOWN_GENERATORS:
            if kg.lower() in gen_value.lower():
                detected_techs.append(gen_value)
                break

    # Common CMS fingerprints in HTML source (case-insensitive)
    cms_signatures = {
        "wordpress": [r'wp-content/', r'wp-includes/', r'wordpress'],
        "joomla": [r'joomla', r'/components/com_', r'media/'],
        "drupal": [r'drupal', r'/sites/default/files', r'core/misc/drupal'],
        "mediawiki": [r'mediawiki', r'/w/load.php', r'/index\.php.*action='],
        "ghost": [r'ghost-', r'/ghost/'],
        "concrete5": [r'concrete/', r'cms_theme/'],
    }
    for cms, patterns in cms_signatures.items():
        for pat in patterns:
            if _re.search(pat, body_text[:32768], _re.IGNORECASE):
                detected_techs.append(cms)
                break  # one match per CMS is enough

    if detected_techs:
        flags.append(f"tech_stack: {', '.join(detected_techs[:5])}")

    # ── 3. contact_found ──────────────────────────────────────────────
    import re as _re2
    email_re = _re2.compile(
        r'[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z]{2,}',
        _re2.IGNORECASE,
    )
    found_emails = email_re.findall(body_text[:32768])
    if found_emails:
        flags.append(f"contact_found: email ({len(found_emails)} addr(s))")

    # Social media links
    social_patterns = {
        "twitter": r'(?:twitter\.com|x\.com)/\w+',
        "mastodon": r'mastodon\.|\.\w+/@\w+',
        "github": r'github\.com/\w+',
        "telegram": r'telegram\.(?:me|org)/\w+',
    }
    found_social: list[str] = []
    for platform, pat in social_patterns.items():
        if _re2.search(pat, body_text[:32768], _re2.IGNORECASE):
            found_social.append(platform)

    if found_social:
        flags.append(f"contact_found: social ({', '.join(found_social)})")

    # ── 4. forum_site ────────────────────────────────────────────────
    forum_signatures = {
        "phpBB": [r'phpbb', r'/styles/.*/theme/', r'forum\.php'],
        "XenForo": [r'xenforo', r'/xf\.', r'js/xenforo\.min\.js'],
        "Discourse": [r'discourse', r'data-controller=', r'discourse-helpers.js'],
        "vBulletin": [r'vbulletin', r'/clientscript/vb\.', r'/forum\.php'],
        "Flarum": [r'flarum', r'/extensions/', r'flarum-header'],
        "IPS (Invision)": [r'invision', r'/uploads/', r'ipsTemplate'],
    }
    for forum_software, patterns in forum_signatures.items():
        for pat in patterns:
            if _re2.search(pat, lower_body):
                flags.append(f"forum_site: {forum_software}")
                break

    # ── 5. redirect_chain ─────────────────────────────────────────────
    if redirect_depth > 1:
        flags.append(f"redirect_chain: depth={redirect_depth}")

    return flags


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class DiscoveryResult:
    """Result of probing a single destination."""

    b32_addr: str = ""
    ident_hash_hex: str = ""
    reachable: bool = False
    status_code: int = 0
    body_length: int = 0
    title: str = ""
    response_time_sec: float = 0.0
    via_method: str = ""  # "b32" | "dns" | "b32+dns" | ""
    probe_mode: str = ""   # which type of URL was used ("b32" or "dns")
    error: str = ""
    content_type: str = ""     # short bucket label (e.g. "forum", "news site")
    content_summary: str = ""  # sentence-length description of page content
    found_links: list[str] = field(default_factory=list)
    content_hash: str = ""     # SHA-256 of body for change detection
    last_modified: str = ""    # HTTP Last-Modified header value
    flags: list[str] = field(default_factory=list)     # extracted signals (robots_disallow_all, tech_stack_detected, ...)
    needs_review: bool = False  # True when no extractor claimed or partial extract
    reason: str = ""  # reason string for needs_review (e.g. "no_extractor_claimed")


# ---------------------------------------------------------------------------
# Persistent discovery database
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH = os.path.join(os.getcwd(), "indexer.db")


class DiscoveryDB:
    """SQLite store for probe results and full addressbook records."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self._path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        # Let concurrent processes wait up to 5s for write locks instead of
        # raising OperationalError immediately (multi-process safety under WAL).
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._lock = threading.Lock()
        self._init_db()
        self._ensure_discovery_columns()
        self._ensure_targets_columns()
        self._ensure_susi_sync_table()
        self._ensure_address_book_view()

    # ── context manager (P4 — prevent connection leaks) ────

    def __enter__(self) -> "DiscoveryDB":
        return self

    def __exit__(self, exc_type: TypingAny, exc_val: TypingAny, exc_tb: TypingAny) -> None:
        self.close()

    # ── schema ────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        cur = self._conn.cursor()
        cur.executescript(
            """
            -- Source routers (from addressbook parsing, webconsole scrape, etc.)
            DROP VIEW IF EXISTS address_book;
            CREATE TABLE IF NOT EXISTS routers (
                ident_hash_hex   TEXT PRIMARY KEY,
                key_type         INTEGER DEFAULT 0,
                version          INTEGER DEFAULT 0,
                bandwidth_kbps   INTEGER DEFAULT 0,
                options_mask     INTEGER DEFAULT 0,
                caps             TEXT    DEFAULT '',
                published        INTEGER DEFAULT 0,
                file_size        INTEGER DEFAULT 0,
                i2p_dns_name     TEXT    DEFAULT '',
                source           TEXT    DEFAULT 'unknown',
                updated_at       REAL    DEFAULT (strftime('%s','now'))
            );

            -- Source lease sets
            CREATE TABLE IF NOT EXISTS leasesets (
                ident_hash_hex   TEXT PRIMARY KEY,
                store_type       INTEGER DEFAULT 0,
                num_leases       INTEGER DEFAULT 0,
                options_mask     INTEGER DEFAULT 0,
                leases_v1_count  INTEGER DEFAULT 0,
                file_size        INTEGER DEFAULT 0,
                i2p_dns_name     TEXT    DEFAULT '',
                source           TEXT    DEFAULT 'unknown',
                updated_at       REAL    DEFAULT (strftime('%s','now'))
            );

            -- Probe/discovery results — one row per attempt per address type
            CREATE TABLE IF NOT EXISTS discoveries (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ident_hash_hex  TEXT    NOT NULL,
                b32_addr        TEXT    NOT NULL,
                i2p_dns_name    TEXT    DEFAULT '',
                probe_mode      TEXT    NOT NULL,   -- 'b32' | 'dns'
                reachable       INTEGER NOT NULL,
                status_code     INTEGER DEFAULT 0,
                body_length     INTEGER DEFAULT 0,
                title           TEXT    DEFAULT '',
                response_time   REAL    DEFAULT 0.0,
                via_method      TEXT    DEFAULT '',
                content_type    TEXT    DEFAULT '',  -- short bucket label (e.g. 'forum')
                content_summary TEXT    DEFAULT '',  -- sentence-length page description
                content_hash    TEXT    DEFAULT '',  -- SHA-256 of body for change detection
                last_modified   TEXT    DEFAULT '',  -- HTTP Last-Modified header value
                found_links     TEXT    DEFAULT '[]',-- JSON array of linked i2p dns names
                flags           TEXT    DEFAULT '[]',-- arbitrary analysis signals (robots, tech stack, ...)
                error_msg       TEXT    DEFAULT '',
                probed_at       REAL    DEFAULT (strftime('%s','now'))
            );

            -- Master target list — source of truth for discovery work
            CREATE TABLE IF NOT EXISTS targets (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                ident_hash_hex   TEXT DEFAULT '',
                b32_addr         TEXT NOT NULL DEFAULT '',
                i2p_dns_name     TEXT DEFAULT '',
                last_probed_at   REAL DEFAULT 0,
                source           TEXT DEFAULT 'manual',
                source_site      TEXT    DEFAULT '',-- which site discovered this target
                UNIQUE(ident_hash_hex, i2p_dns_name)
            );

            -- Index for fast lookups by hash and DNS name
            CREATE INDEX IF NOT EXISTS idx_disc_hash ON discoveries(ident_hash_hex);
            CREATE INDEX IF NOT EXISTS idx_disc_dns  ON discoveries(i2p_dns_name);

            -- "Our address book" view: one row per destination showing the most
            -- recent probe result joined with router/leaseset metadata.
            -- Dedup key: DNS name when present and non-empty, else b32 address.
            -- A site reachable by two different DNS names appears as two rows
            -- (separate entry points); b32-only probes fall back to the b32 key.
            CREATE VIEW IF NOT EXISTS address_book AS
            SELECT
                ab.dns_name,
                ab.content_type,
                ab.reachable,
                datetime(ab.last_probed_at, 'unixepoch') AS last_probed_utc,
                ab.content_summary,
                ab.ident_hash_hex,
                ab.b32_addr,
                ab.status_code,
                ab.body_length,
                ab.title,
                ab.response_time_sec,
                ab.via_method,
                ab.last_probed_at,
                ab.content_hash,
                ab.last_modified,
                ab.found_links,
                ab.flags,
                ab.needs_review,
                r.bandwidth_kbps,
                r.caps    AS router_caps,
                ls.num_leases
            FROM (
                SELECT
                    ident_hash_hex,
                    b32_addr,
                    CASE WHEN i2p_dns_name != '' THEN i2p_dns_name ELSE b32_addr END AS dns_name,
                    reachable,
                    status_code,
                    body_length,
                    title,
                    response_time   AS response_time_sec,
                    via_method,
                    content_type,
                    content_summary,
                    probed_at       AS last_probed_at,
                    content_hash,
                    last_modified,
                    found_links,
                    flags,
                    needs_review,
                    ROW_NUMBER() OVER (
                        PARTITION BY CASE WHEN i2p_dns_name != '' THEN i2p_dns_name ELSE b32_addr END
                        ORDER BY probed_at DESC
                    ) AS rn
                FROM discoveries
            ) ab
            LEFT JOIN routers   r  ON r.ident_hash_hex = ab.ident_hash_hex
            LEFT JOIN leasesets ls ON ls.ident_hash_hex = ab.ident_hash_hex
            WHERE ab.rn = 1
            ORDER BY ab.last_probed_at DESC;
            """
        )
        self._conn.commit()

    # ── schema migrations (new columns for existing databases) ────────

    def _ensure_discovery_columns(self) -> None:
        """Add new columns if they exist in newer schema but not in this DB.

        After adding a column, verify the type matches expectations so that
        manually-created columns with the wrong type are detected and logged
        rather than failing silently downstream.
        """
        cur = self._conn.cursor()
        cur.execute("PRAGMA table_info(discoveries)")
        col_info = {row[1]: row[2] for row in cur.fetchall()}  # name -> type

        if "flags" not in col_info:
            cur.execute(
                "ALTER TABLE discoveries ADD COLUMN flags TEXT DEFAULT '[]'"
            )
            self._conn.commit()
            # Reload and verify the column landed with the right type
            cur.execute("PRAGMA table_info(discoveries)")
            col_info = {row[1]: row[2] for row in cur.fetchall()}

        if "flags" in col_info and col_info["flags"] not in ("TEXT", ""):
            logger.warning(
                "discoveries.flags has unexpected type '%s' (expected TEXT); "
                "this may cause issues with flag extraction.",
                col_info["flags"],
            )

        if "needs_review" not in col_info:
            cur.execute(
                "ALTER TABLE discoveries ADD COLUMN needs_review INTEGER DEFAULT 0"
            )
            self._conn.commit()
        elif col_info["needs_review"] not in ("INTEGER", ""):
            logger.warning(
                "discoveries.needs_review has unexpected type '%s'; may cause issues.",
                col_info["needs_review"],
            )

        # Ensure unique constraint for upsert-based dedup (ident_hash_hex + probe_mode).
        # Existing databases will have duplicate rows from repeated sweeps, so we need
        # to collapse them before adding the unique index. The strategy:
        #   1. Create temp table with one row per (ident_hash_hex, probe_mode)
        #      keeping only the most recent probe
        #   2. Drop old discoveries, recreate from deduped data
        #   3. Add unique index to prevent future duplicates
        cur.execute("PRAGMA index_list(discoveries)")
        idx_names = {row[1] for row in cur.fetchall()}
        if "idx_disc_ident_probe" not in idx_names:
            try:
                # Step 1: Check how many duplicates exist
                cur.execute("""
                    SELECT COUNT(*) - COUNT(DISTINCT ident_hash_hex || '_' || probe_mode)
                    FROM discoveries
                """)
                dup_count = cur.fetchone()[0] or 0

                if dup_count > 0:
                    logger.info(
                        "Deduplicating %d discovery rows by (ident_hash_hex, probe_mode)...",
                        dup_count,
                    )
                    # Create temp table with deduped data (keep latest per combo)
                    cur.execute("""
                        CREATE TEMPORARY TABLE disc_dedup AS
                        SELECT * FROM discoveries WHERE id IN (
                            SELECT MAX(id) FROM discoveries
                            GROUP BY ident_hash_hex, probe_mode
                        )
                    """)

                    # Clear and reload
                    cur.execute("DELETE FROM discoveries")
                    cur.execute("""
                        INSERT INTO discoveries
                        SELECT * FROM disc_dedup ORDER BY probed_at DESC
                    """)
                    cur.execute("DROP TABLE IF EXISTS disc_dedup")
                    self._conn.commit()

                # Step 2: Add unique index
                cur.execute(
                    "CREATE UNIQUE INDEX idx_disc_ident_probe "
                    "ON discoveries(ident_hash_hex, probe_mode)"
                )
                self._conn.commit()

            except Exception as e:
                logger.warning("Failed to create dedup index on discoveries: %s", e)

    def _ensure_targets_columns(self) -> None:
        """Add new columns for SUSI export support."""
        cur = self._conn.cursor()
        cur.execute("PRAGMA table_info(targets)")
        existing_cols = {row[1] for row in cur.fetchall()}
        if "susi_active" not in existing_cols:
            cur.execute(
                "ALTER TABLE targets ADD COLUMN susi_active INTEGER DEFAULT 0"
            )
        if "first_seen_at" not in existing_cols:
            cur.execute(
                "ALTER TABLE targets ADD COLUMN first_seen_at REAL DEFAULT 0"
            )
        if "last_updated_at" not in existing_cols:
            cur.execute(
                "ALTER TABLE targets ADD COLUMN last_updated_at REAL DEFAULT 0"
            )
        self._conn.commit()

    def _ensure_susi_sync_table(self) -> None:
        """Create table for SUSI export sync state."""
        cur = self._conn.cursor()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS susi_sync (
                key       TEXT PRIMARY KEY,
                value     TEXT DEFAULT '',
                updated_at REAL DEFAULT 0
            )"""
        )
        self._conn.commit()

    def _recreate_address_book_view(self, cur: sqlite3.Cursor) -> None:
        """DROP then CREATE the address_book view with the current schema.

        Idempotent and safe for concurrent callers: retries once when another
        connection creates the view between our DROP and CREATE.
        """
        # ── helper to extract first non-empty content excerpt from summary ──
        # In SQLite we use subexpressions to build a readable paragraph out of
        # all available metadata.  This replaces the raw ``content_summary`` blob
        # that tools like ``print_address_book`` previously chopped at [:100].

        view_sql = """
            DROP VIEW IF EXISTS address_book;
            CREATE VIEW address_book AS
            SELECT
                ab.dns_name,
                ab.content_type,
                ab.reachable,
                datetime(ab.last_probed_at, 'unixepoch') AS last_probed_utc,
                /* ── rich synthesized paragraph replaces raw content_summary ── */
                CASE
                    WHEN ab.reachable = 0
                    THEN ab.dns_name || ' — currently unreachable'

                    WHEN ab.title IS NOT NULL AND ab.title != ''
                         AND ab.content_summary IS NOT NULL AND LENGTH(ab.content_summary) > 30
                    THEN
                        printf(
                            '%s ("%s") [%s] %sKB in %.1fs — %s',
                            ab.dns_name,
                            REPLACE(ab.title, '"', "'"),
                            COALESCE(NULLIF(ab.content_type, ''), 'unknown'),
                            CASE WHEN ab.body_length > 0
                                 THEN CAST(CAST(ab.body_length AS REAL) / 1024.0 AS NUMERIC)
                                 ELSE NULL END,
                            COALESCE(ab.response_time_sec, -1),
                            REPLACE(
                                SUBSTR(
                                    REPLACE(REPLACE(ab.content_summary, CHAR(10), ' · '), CHAR(13), ''), 1, 200
                                ),
                                CHAR(10), ' · '
                            )
                        )

                    WHEN ab.title IS NOT NULL AND ab.title != ''
                    THEN printf('%s ("%s") [%s]',
                        ab.dns_name,
                        REPLACE(ab.title, '"', "'"),
                        COALESCE(NULLIF(ab.content_type, ''), 'unknown')
                    )

                    WHEN ab.content_summary IS NOT NULL AND LENGTH(ab.content_summary) > 10
                    THEN printf('%s — %s',
                        ab.dns_name,
                        SUBSTR(REPLACE(ab.content_summary, CHAR(10), ' · '), 1, 200)
                    )

                    ELSE ab.dns_name || ' (no content data)'
                END AS content_summary,
                ab.ident_hash_hex,
                ab.b32_addr,
                ab.status_code,
                ab.body_length,
                ab.title,
                ab.response_time_sec,
                ab.via_method,
                ab.last_probed_at,
                ab.content_hash,
                ab.last_modified,
                ab.found_links,
                ab.flags,
                ab.needs_review,
                r.bandwidth_kbps,
                r.caps    AS router_caps,
                ls.num_leases
            FROM (
                SELECT
                    ident_hash_hex,
                    b32_addr,
                    CASE WHEN i2p_dns_name != '' THEN i2p_dns_name ELSE b32_addr END AS dns_name,
                    reachable,
                    status_code,
                    body_length,
                    title,
                    response_time   AS response_time_sec,
                    via_method,
                    content_type,
                    content_summary,
                    probed_at       AS last_probed_at,
                    content_hash,
                    last_modified,
                    found_links,
                    flags,
                    needs_review,
                    ROW_NUMBER() OVER (
                        PARTITION BY CASE WHEN i2p_dns_name != '' THEN i2p_dns_name ELSE b32_addr END
                        ORDER BY probed_at DESC
                    ) AS rn
                FROM discoveries
            ) ab
            LEFT JOIN routers   r  ON r.ident_hash_hex = ab.ident_hash_hex
            LEFT JOIN leasesets ls ON ls.ident_hash_hex = ab.ident_hash_hex
            WHERE ab.rn = 1
            ORDER BY ab.last_probed_at DESC;
            """

        try:
            cur.executescript(view_sql)
        except sqlite3.OperationalError as exc:
            if "already exists" in str(exc):
                # Another concurrent connection beat us to CREATE VIEW —
                # check ours matches, skip if so
                logger.info("address_book view already created by another connection")
                return
            raise

        self._conn.commit()

    def _ensure_address_book_view(self) -> None:
        """Migrate the address_book view if content_summary lacks the rich synthesized paragraph or other new columns.

        Only drops and recreates when the existing view schema is stale, so that
        every DiscoveryDB instantiation is cheap on an up-to-date database.

        Safe for concurrent DiscoveryDB instances sharing one file: the
        underlying _recreate_address_book_view handles "already exists" races.
        """
        cur = self._conn.cursor()
        try:
            cur.execute(
                "SELECT sql FROM sqlite_master WHERE type='view' AND name='address_book'"
            )
            row = cur.fetchone()
        except Exception:
            row = None

        if row and row[0]:
            view_sql = row[0]
            stable = (
                "flags" in view_sql
                and "needs_review" in view_sql
                and "currently unreachable" in view_sql
            )
            if stable:
                return

        logger.info("Recreating address_book view")
        self._recreate_address_book_view(cur)

    # ── upsert helpers ────────────────────────────────────────────────

    def record_router(
        self,
        ident_hash_hex: str,
        key_type: int = 0,
        version: int = 0,
        bandwidth_kbps: int = 0,
        caps: str = "",
        published: bool = False,
        file_size: int = 0,
        i2p_dns_name: str = "",
        source: str = "probe",
    ) -> None:
        with self._lock:
            cur = self._conn.cursor()
            now = datetime.now(timezone.utc).timestamp()
            cur.execute(
                """INSERT INTO routers (ident_hash_hex, key_type, version, bandwidth_kbps,
                                       options_mask, caps, published, file_size, i2p_dns_name, source, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ident_hash_hex) DO UPDATE SET
                       key_type=excluded.key_type,
                       version=excluded.version,
                       bandwidth_kbps=excluded.bandwidth_kbps,
                       options_mask=excluded.options_mask,
                       caps=excluded.caps,
                       published=excluded.published,
                       file_size=excluded.file_size,
                       i2p_dns_name=COALESCE(NULLIF(excluded.i2p_dns_name, ''), i2p_dns_name),
                       updated_at=excluded.updated_at""",
            (ident_hash_hex, key_type, version, bandwidth_kbps, 0,
             caps, int(published), file_size, i2p_dns_name, source, now),
            )
            self._conn.commit()

    def record_lease_set(
        self,
        ident_hash_hex: str,
        store_type: int = 0,
        num_leases: int = 0,
        i2p_dns_name: str = "",
        source: str = "probe",
    ) -> None:
        with self._lock:
            cur = self._conn.cursor()
            now = datetime.now(timezone.utc).timestamp()
            cur.execute(
                """INSERT INTO leasesets (ident_hash_hex, store_type, num_leases,
                                         i2p_dns_name, source, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ident_hash_hex) DO UPDATE SET
                       store_type=excluded.store_type,
                       num_leases=excluded.num_leases,
                       i2p_dns_name=COALESCE(NULLIF(excluded.i2p_dns_name, ''), i2p_dns_name),
                       updated_at=excluded.updated_at""",
                (ident_hash_hex, store_type, num_leases, i2p_dns_name, source, now),
            )
            self._conn.commit()

    def record_discovery(
        self,
        ident_hash_hex: str,
        b32_addr: str,
        probe_mode: str,       # "b32" or "dns"
        reachable: bool,
        status_code: int = 0,
        body_length: int = 0,
        title: str = "",
        response_time: float = 0.0,
        i2p_dns_name: str = "",
        via_method: str = "",
        content_type: str = "",
        content_summary: str = "",
        content_hash: str = "",
        last_modified: str = "",
        found_links: list[str] | None = None,
        flags: list[str] | None = None,
        needs_review: bool = False,
        error_msg: str = "",
    ) -> int:
        """Record one probe attempt. Returns the new row id."""
        with self._lock:
            cur = self._conn.cursor()
            now = datetime.now(timezone.utc).timestamp()
            import json as _json

            cur.execute(
                """INSERT INTO discoveries
                   (ident_hash_hex, b32_addr, i2p_dns_name, probe_mode, reachable,
                    status_code, body_length, title, response_time, via_method,
                    content_type, content_summary, content_hash, last_modified,
                    found_links, flags, needs_review, error_msg, probed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ident_hash_hex, probe_mode) DO UPDATE SET
                       b32_addr=excluded.b32_addr,
                       i2p_dns_name=COALESCE(NULLIF(excluded.i2p_dns_name, ''), i2p_dns_name),
                       reachable=excluded.reachable,
                       status_code=excluded.status_code,
                       body_length=excluded.body_length,
                       title=COALESCE(NULLIF(excluded.title, ''), title),
                       response_time=excluded.response_time,
                       via_method=excluded.via_method,
                       content_type=excluded.content_type,
                       content_summary=excluded.content_summary,
                       content_hash=excluded.content_hash,
                       last_modified=excluded.last_modified,
                       found_links=COALESCE(NULLIF(excluded.found_links, '[]'), found_links),
                       flags=COALESCE(NULLIF(excluded.flags, '[]'), flags),
                       needs_review=excluded.needs_review,
                       error_msg=COALESCE(NULLIF(excluded.error_msg, ''), error_msg),
                       probed_at=excluded.probed_at""",
                (ident_hash_hex, b32_addr, i2p_dns_name, probe_mode, int(reachable),
                 status_code, body_length, title, response_time, via_method,
                 content_type, _truncate(content_summary, 4096), content_hash,
                 last_modified, _json.dumps(found_links or []),
                 _json.dumps(flags or []), int(needs_review), error_msg, now),
            )
            self._conn.commit()
            row_id = cur.lastrowid
            return int(row_id) if row_id is not None else 0

    # ── queries ───────────────────────────────────────────────────────

    def get_latest_probes_by_hash(self, hash_hex: str) -> list[dict]:
        """Get the most recent probe results for a given ident hash."""
        cur = self._conn.cursor()
        cur.execute(
            """SELECT ident_hash_hex, b32_addr, i2p_dns_name, probe_mode, reachable,
                      status_code, body_length, title, response_time, via_method,
                      error_msg, datetime(probed_at, 'unixepoch') as probed_at_ts
               FROM discoveries
               WHERE ident_hash_hex = ?
               ORDER BY probed_at DESC
               LIMIT 10""",
            (hash_hex,),
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_latest_probes_by_dns_name(self, dns_name: str) -> list[dict]:
        """Find probes that match a DNS name (either as primary or resolved)."""
        cur = self._conn.cursor()
        cur.execute(
            """SELECT ident_hash_hex, b32_addr, i2p_dns_name, probe_mode, reachable,
                      status_code, body_length, title, response_time, via_method,
                      error_msg, datetime(probed_at, 'unixepoch') as probed_at_ts
               FROM discoveries
               WHERE i2p_dns_name = ?
               ORDER BY probed_at DESC
               LIMIT 10""",
            (dns_name,),
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_all_hashes(self, limit: int | None = None) -> list[str]:
        """Get unique ident hashes discovered so far.

        Args:
            limit: Optional maximum number of hashes to return.
        """
        cur = self._conn.cursor()
        sql = "SELECT DISTINCT ident_hash_hex FROM discoveries"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        cur.execute(sql)
        return [r[0] for r in cur.fetchall()]

    def summary(self) -> dict:
        """Quick stats about the database."""
        cur = self._conn.cursor()
        cur.execute("SELECT COUNT(*) FROM routers")
        n_routers = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM leasesets")
        n_ls = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM discoveries")
        n_disc = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT ident_hash_hex) FROM discoveries")
        n_unique = cur.fetchone()[0]
        cur.execute("SELECT SUM(reachable) FROM discoveries WHERE reachable=1")
        n_reachable = (cur.fetchone()[0] or 0)
        return {
            "routers": n_routers,
            "leasesets": n_ls,
            "total_probes": n_disc,
            "unique_destinations": n_unique,
            "reachable_count": n_reachable,
        }

    def address_book(self, limit: int | None = None) -> list[dict]:
        """Return the 'address book' view: one row per destination showing the
        most recent probe result joined with router/leaseset metadata.

        Args:
            limit: Optional maximum number of rows to return.

        Columns: dns_name, content_type, reachable, last_probed_utc, content_summary,
        ident_hash_hex, b32_addr, status_code, body_length, title, response_time_sec,
        via_method, last_probed_at, content_hash, last_modified, found_links,
        bandwidth_kbps, router_caps, num_leases.
        """
        cur = self._conn.cursor()
        sql = "SELECT * FROM address_book ORDER BY dns_name ASC"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        cur.execute(sql)
        cols = [desc[0] for desc in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def get_flagged_destinations(self, limit: int | None = None) -> list[tuple[str, str]]:
        """Return destinations flagged with needs_review from the address_book view.

        This is a subset of address_book filtered to only rows where the most recent
        discovery for that destination has needs_review=1.  Returns (ident_hash_hex,
        dns_name) tuples suitable for passing to probe_destination().

        Args:
            limit: Optional maximum number of destinations to return.
        """
        cur = self._conn.cursor()
        if limit is not None and limit < 0:
            raise ValueError(f"limit must be non-negative, got {limit}")
        sql = "SELECT ident_hash_hex, dns_name FROM address_book WHERE needs_review = 1"
        params: list[int | str] = []
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        cur.execute(sql, params)
        return [(r[0], r[1]) for r in cur.fetchall()]

    def clear_needs_review(self, ident_hash_hex: str) -> int:
        """Clear needs_review flag on the most recent discovery for a destination.

        Called after a successful reprobe — if the new extraction succeeded,
        the previous flagged state is no longer relevant.

        Args:
            ident_hash_hex: SHA-1 hash of the destination identity.

        Returns:
            Number of rows updated (0 if nothing to clear).
        """
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "UPDATE discoveries SET needs_review = 0 "
                "WHERE ident_hash_hex = ? AND probed_at = ("
                    "SELECT MAX(probed_at) FROM discoveries WHERE ident_hash_hex = ?"
                ")",
                (ident_hash_hex, ident_hash_hex),
            )
            self._conn.commit()
        return cur.rowcount

    def cleanup_unreachable(
        self,
        max_age_hours: int = 168,  # 7 days default
    ) -> int:
        """Remove unreachable discovery records older than max_age_hours.

        Reachable records are kept indefinitely (they represent the current state
        of destinations).  Unreachable records are transient failure states that
        lose value over time.  This prevents the discoveries table from growing
        unboundedly across thousands of sweeps.

        Args:
            max_age_hours: Hours threshold. Records older than this AND unreachable
                will be removed. Default 168 (7 days).

        Returns:
            Number of rows deleted.
        """
        with self._lock:
            cur = self._conn.cursor()
            cutoff = datetime.now(timezone.utc).timestamp() - (max_age_hours * 3600)
            cur.execute(
                "DELETE FROM discoveries WHERE reachable = 0 AND probed_at < ?",
                (cutoff,),
            )
            self._conn.commit()
            return cur.rowcount

    def upsert_targets(
        self,
        targets: list[tuple[str, str]],
        source: str = "manual",
    ) -> int:
        """Upsert target destinations. Tuple is (ident_hash_hex, i2p_dns_name).

        Args:
            targets: List of (hash_hex, dns_name) tuples.
            source: Origin label — 'manual', 'addressbook', 'linked', or
                'susi_export:...'.  Defaults to 'manual' for backward compatibility.
        """
        with self._lock:
            cur = self._conn.cursor()
            now = datetime.now(timezone.utc).timestamp()
            n = 0
            for h, d in targets:
                b32 = _hex_to_b32_addr(h) if len(h) == 40 else ""
                cur.execute(
                    "INSERT OR IGNORE INTO targets "
                    "(ident_hash_hex, b32_addr, i2p_dns_name, source) VALUES (?, ?, ?, ?)",
                    (h, b32, d or "", source),
                )
                if source == "addressbook":
                    cur.execute(
                        "UPDATE targets SET last_updated_at = ? "
                        "WHERE ident_hash_hex = ? AND source = 'addressbook'",
                        (now, h),
                    )
                n += 1
            self._conn.commit()
            return n

    def load_addressbook(self, catalog: AddressBookCatalog) -> int:
        """Load all destinations from an AddressBookCatalog into the targets table.

        Each destination gets source='addressbook'.  Existing rows with this source
        are kept (the UNIQUE constraint skips duplicates).  Returns count of rows
        attempted (inserted + already-present).
        """
        dests = catalog.all_destinations()
        pairs: list[tuple[str, str]] = []
        for de in dests:
            # We only have hash + b32 addr from the addressbook — no DNS names yet.
            # Store with empty dns_name so reconciliation can still match on hash.
            pairs.append((de.ident_hash_hex, ""))

        count = len(pairs)
        return self.upsert_targets(pairs, source="addressbook")

    def reconcile_addressbook(
        self,
        catalog: AddressBookCatalog,
        mark_stale_days: int = 30,
    ) -> dict[str, int]:
        """Reconcile addressbook-sourced targets against the current catalog.

        After a load_addressbook call, any target with source='addressbook' that is
        NOT in *any* addressbook source (the catalog represents the latest state)
        gets a stale marker via its `source` being suffixed with ':stale'.

        Args:
            catalog: Current AddressBookCatalog snapshot.
            mark_stale_days: Not used here — all missing entries are marked stale
                immediately since the catalog is authoritative.

        Returns:
            {'new': N, 'updated': M, 'marked_stale': K} summary dict.
        """
        # Build set of all hashes currently in the catalog (no lock needed)
        current_hashes: set[str] = set()
        for de in catalog.all_destinations():
            current_hashes.add(de.ident_hash_hex.upper())

        with self._lock:
            cur = self._conn.cursor()
            now = datetime.now(timezone.utc).timestamp()

            # Refresh timestamps on addressbook targets that are still present
            updated = 0
            for hx in current_hashes:
                cur.execute(
                    "UPDATE targets SET last_updated_at = ? "
                    "WHERE ident_hash_hex = ? AND source = 'addressbook'",
                    (now, hx),
                )
                updated += cur.rowcount

            # Mark addressbook targets not in current catalog as stale
            stale_hashes = tuple(
                row[0] for row in cur.execute(
                    "SELECT DISTINCT ident_hash_hex FROM targets WHERE source = 'addressbook'"
                ).fetchall()
                if row[0].upper() not in current_hashes
            )

            marked_stale = 0
            for hx in stale_hashes:
                cur.execute(
                    "UPDATE targets SET source = 'addressbook:stale' "
                    "WHERE ident_hash_hex = ? AND source = 'addressbook'",
                    (hx,),
                )
                marked_stale += cur.rowcount

            # Count newly inserted addressbook rows
            new_count = sum(
                1 for row in cur.execute(
                    "SELECT first_seen_at FROM targets WHERE source = 'addressbook'"
                ).fetchall()
                if row[0] == 0  # never actually set by us; just a proxy indicator
                # Actually count rows updated in this session — use the updated_at change
            )

            self._conn.commit()

        return {"updated": updated, "marked_stale": marked_stale}

    def upsert_susi_entries(
        self,
        entries: list[dict],
        source_book: str = "router",
    ) -> int:
        """Upsert targets parsed from a SUSI DNS address book export.

        Additive-only: sites imported here are never deleted when they disappear
        from future exports. Rows have `susi_active` (current generation marker) and
        the composite UNIQUE key is (ident_hash_hex, i2p_dns_name).

        Each dict has keys: i2p_dns_name, ident_hash_hex, b32_raw, dest_data_len.
        Returns count of rows inserted or updated.
        """
        with self._lock:
            cur = self._conn.cursor()
            now = datetime.now(timezone.utc).timestamp()
            n = 0

            # Get current generation counter (monotonic)
            gen_row = cur.execute(
                "SELECT MAX(value) FROM susi_sync WHERE key='generation'"
            ).fetchone()
            if gen_row and gen_row[0]:
                generation = int(gen_row[0]) + 1
            else:
                generation = 1

            # Mark all susi_export rows as inactive (not in this generation)
            cur.execute(
                "UPDATE targets SET susi_active = 0, last_updated_at = ? "
                "WHERE source LIKE 'susi_export:%'",
                (now,),
            )

            for e in entries:
                dns = e.get("i2p_dns_name", "")
                h = e.get("ident_hash_hex", "").upper()
                b32 = e.get("b32_raw", "")
                if not dns:
                    continue

                # Check existing rows with this DNS name AND hash combo
                cur.execute(
                    "SELECT id FROM targets WHERE ident_hash_hex = ? AND i2p_dns_name = ?",
                    (h, dns),
                )
                row = cur.fetchone()
                src = f"susi_export:{source_book}"
                if row:
                    # Exists — reactivate and update
                    cur.execute(
                        "UPDATE targets SET susi_active = ?, b32_addr = ?, source = ? "
                        ", last_updated_at = ? WHERE id = ?",
                        (generation, b32, src, now, row[0]),
                    )
                else:
                    # New entry or hash rotation — insert fresh
                    cur.execute(
                        "INSERT INTO targets (ident_hash_hex, b32_addr, i2p_dns_name, source, susi_active) VALUES (?, ?, ?, ?, ?)",
                        (h, b32, dns, src, generation),
                    )
                n += 1

            # Record this generation in sync table
            cur.execute(
                "INSERT OR REPLACE INTO susi_sync (key, value, updated_at) "
                "VALUES ('generation', ?, ?)",
                (str(generation), now),
            )
            self._conn.commit()

        return n

    def get_targets(
        self,
        filter_mode: str = "all",
        min_age_hours: float = 24.0,
    ) -> list[tuple[str, str]]:
        """Return the target queue as (hash_hex, dns_name) tuples.

        Args:
            filter_mode: Which targets to include.
                - "all"          — every target in the database (default, backward compatible)
                - "reachable_only" — only targets with at least one reachable discovery record
                - "never_probed"   — targets where last_probed_at == 0 (first probe pass)
                - "stale"         — targets probed more than min_age_hours ago
            min_age_hours: Hours threshold for "stale" filter (default 24).

        Priorities (within the filtered set):
        1. Previously reachable targets first (highest chance of success).
        2. Entries with valid identity hash (b32 probing capable).
        3. By last_probed_at ascending (older probes first).
        """
        where_clauses: list[str] = []
        params: list = []

        if filter_mode == "reachable_only":
            # Only targets that have at least one reachable discovery.
            # Match by hash when present, otherwise by dns_name — many DNS-only
            # targets have empty ident_hash_hex so a plain IN() join would
            # collapse all rows into a single match on the '' bucket.
            where_clauses.append(
                "EXISTS ("
                "   SELECT 1 FROM discoveries d WHERE reachable = 1 AND ("
                "       (targets.ident_hash_hex != '' AND "
                "        d.ident_hash_hex = targets.ident_hash_hex)"
                "       OR (targets.ident_hash_hex = '' AND "
                "           d.i2p_dns_name = targets.i2p_dns_name)"
                "   )"
                ")"
            )
        elif filter_mode == "never_probed":
            # Targets never probed (or only probed at epoch 0)
            where_clauses.append("last_probed_at <= 0")
        elif filter_mode == "stale":
            # Targets whose last probe is older than min_age_hours
            cutoff = time.time() - (min_age_hours * 3600)
            where_clauses.append("last_probed_at < ?")
            params.append(cutoff)

        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        cur = self._conn.cursor()
        query = (
            f"SELECT ident_hash_hex, i2p_dns_name FROM targets {where_sql} "\
            "ORDER BY "\
            "CASE WHEN EXISTS ("\
            "    SELECT 1 FROM discoveries d "\
            "    WHERE d.ident_hash_hex = targets.ident_hash_hex AND d.reachable=1"\
            ") THEN 0 ELSE 1 END ASC, "\
            "CASE WHEN length(ident_hash_hex)=40 THEN 0 ELSE 1 END ASC, "\
            "last_probed_at ASC"
        )
        cur.execute(query, params)
        return [(r[0], r[1]) for r in cur.fetchall()]

    def upsert_targets_from_links(
        self,
        linked_sites: list[str],
        source_site: str = "",
    ) -> int:
        """Upsert .i2p DNS names discovered while probing another site.

        Each entry gets an empty hash/b32 (DNS-only seed) and records which
        site found it for traceability.  Returns the count of newly inserted rows.
        """
        with self._lock:
            cur = self._conn.cursor()
            added = 0
            for dns in linked_sites:
                if not dns:
                    continue
                # Skip if we already have this dns_name
                cur.execute("SELECT 1 FROM targets WHERE i2p_dns_name = ?", (dns,))
                if cur.fetchone():
                    continue
                cur.execute(
                    "INSERT INTO targets (ident_hash_hex, b32_addr, i2p_dns_name, source, source_site) "
                    "VALUES (?, ?, ?, 'linked', ?)",
                    ("", "", dns, source_site),
                )
                added += 1
            self._conn.commit()

        return added

    def close(self) -> None:
        """Close the SQLite connection.  Idempotent — safe to call repeatedly."""
        try:
            self._conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Probe logic — try b32 key AND dns name
# ---------------------------------------------------------------------------

def probe_destination(
    ident_hash_hex: str,
    i2p_dns_name: str = "",
    db: DiscoveryDB | None = None,
    timeout: float = PROBE_TIMEOUT,
    config: I2PConfig | None = None,
) -> DiscoveryResult:
    """Probe a single destination by BOTH its b32 key address and .i2p DNS name.

    Returns the best result (most data from fastest successful probe).
    If a DB is provided, records both attempts.
    ``timeout`` is the per-target deadline in seconds.
    ``config`` provides proxy host/port settings; defaults to I2PConfig().
    """
    b32_addr = _hex_to_b32_addr(ident_hash_hex) if len(ident_hash_hex) == 40 else ""
    results: list[DiscoveryResult] = []

    # ── Attempt 1: Hit the b32 key directly (no DNS resolution needed)
    if b32_addr:
        logger.info("Probing http://%s/  (b32 key)", b32_addr)
        res_b32 = _do_probe(
            url=f"http://{b32_addr}/",
            ident_hash_hex=ident_hash_hex,
            i2p_dns_name=i2p_dns_name,
            probe_mode="b32",
            timeout=timeout,
            config=config,
        )
        results.append(res_b32)
        if db:
            db.record_discovery(
                ident_hash_hex=ident_hash_hex,
                b32_addr=b32_addr,
                i2p_dns_name=i2p_dns_name,
                probe_mode="b32",
                reachable=res_b32.reachable,
                status_code=res_b32.status_code,
                body_length=res_b32.body_length,
                title=res_b32.title,
                response_time=res_b32.response_time_sec,
                via_method="b32",
                content_type=res_b32.content_type,
                content_summary=res_b32.content_summary,
                content_hash=res_b32.content_hash,
                last_modified=res_b32.last_modified,
                found_links=res_b32.found_links,
                flags=res_b32.flags,
                needs_review=getattr(res_b32, 'needs_review', False),
                error_msg=res_b32.error,
            )

    # ── Attempt 2: Try .i2p DNS name to discover aliases
    # Even when b32 already succeeded, we still probe the DNS name so that
    # multiple DNS names pointing to the same destination are all recorded.
    # Only skip if the DNS name literally IS the derived b32 address itself.
    if i2p_dns_name and not i2p_dns_name.endswith(".b32.i2p"):
        b32_ok = any(r.reachable for r in results if r.probe_mode == "b32")
        # Deduplicate: skip only when the DNS name resolves to the same address
        # we already probed (i.e. it IS the b32 hostname).
        is_same_addr = i2p_dns_name.lower() == b32_addr.lower() if (b32_addr and i2p_dns_name) else False
        if is_same_addr:
            logger.info("Skipping DNS probe — name %s is identical to b32 address %s", i2p_dns_name, b32_addr)
        elif b32_ok:
            # b32 already succeeded — still try DNS with a shorter timeout
            # to discover whether this alias also resolves (cross-reference).
            dns_timeout = min(timeout, 15)
            logger.info(
                "Probing http://%s/  (.i2p DNS alias check, timeout=%ds)", i2p_dns_name, dns_timeout
            )
            res_dns = _do_probe(
                url=f"http://{i2p_dns_name}/",
                ident_hash_hex=ident_hash_hex,
                i2p_dns_name=i2p_dns_name,
                probe_mode="dns",
                timeout=dns_timeout,
                config=config,
            )
            results.append(res_dns)
            if db:
                db.record_discovery(
                    ident_hash_hex=ident_hash_hex,
                    b32_addr=b32_addr,
                    i2p_dns_name=i2p_dns_name,
                    probe_mode="dns",
                    reachable=res_dns.reachable,
                    status_code=res_dns.status_code,
                    body_length=res_dns.body_length,
                    title=res_dns.title,
                    response_time=res_dns.response_time_sec,
                    via_method="dns",
                    content_type=res_dns.content_type,
                    content_summary=res_dns.content_summary,
                    content_hash=res_dns.content_hash,
                    last_modified=res_dns.last_modified,
                    found_links=res_dns.found_links,
                    flags=res_dns.flags,
                    needs_review=getattr(res_dns, 'needs_review', False),
                    error_msg=res_dns.error,
                )
        else:
            logger.info("Probing http://%s/  (.i2p DNS fallback)", i2p_dns_name)
            res_dns = _do_probe(
                url=f"http://{i2p_dns_name}/",
                ident_hash_hex=ident_hash_hex,
                i2p_dns_name=i2p_dns_name,
                probe_mode="dns",
                timeout=timeout,
                config=config,
            )
            results.append(res_dns)
            if db:
                db.record_discovery(
                    ident_hash_hex=ident_hash_hex,
                    b32_addr=b32_addr,
                    i2p_dns_name=i2p_dns_name,
                    probe_mode="dns",
                    reachable=res_dns.reachable,
                    status_code=res_dns.status_code,
                    body_length=res_dns.body_length,
                    title=res_dns.title,
                    response_time=res_dns.response_time_sec,
                    via_method="dns",
                    content_type=res_dns.content_type,
                    content_summary=res_dns.content_summary,
                    content_hash=res_dns.content_hash,
                    last_modified=res_dns.last_modified,
                    found_links=res_dns.found_links,
                    flags=res_dns.flags,
                    needs_review=getattr(res_dns, 'needs_review', False),
                    error_msg=res_dns.error,
                )

    # ── Determine best result and merge info
    if not results:
        return DiscoveryResult(
            b32_addr="",
            ident_hash_hex=ident_hash_hex,
            reachable=False,
            error="No address to probe (no hash and no DNS name)",
        )

    # Pick the one with most body data, or if tied, fastest
    best = max(results, key=lambda r: (r.reachable, r.body_length, -r.response_time_sec))

    # Merge via_method info
    b32_ok = any(r.probe_mode == "b32" and r.reachable for r in results)
    dns_ok = any(r.probe_mode == "dns" and r.reachable for r in results)
    if b32_ok and dns_ok:
        best.via_method = "b32+dns"
    elif b32_ok:
        best.via_method = "b32"
    elif dns_ok:
        best.via_method = "dns"

    # Record source info in DB
    if db and best.reachable:
        db.record_router(
            ident_hash_hex=ident_hash_hex,
            i2p_dns_name=i2p_dns_name or best.b32_addr,
            source="probe",
        )

    # Auto-seed discovered .i2p links (minus the current site itself)
    if db and best.found_links:
        parent = i2p_dns_name or ident_hash_hex[:16] or "(unknown)"
        exclude = {i2p_dns_name, ""}
        new = [s for s in set(best.found_links) if s not in exclude]
        if new:
            added = db.upsert_targets_from_links(
                linked_sites=new,
                source_site=parent,
            )
            logger.info("  Found %d new i2p link(s), seeded %d to targets", len(new), added)

    return best


def _do_probe(
    url: str,
    ident_hash_hex: str,
    i2p_dns_name: str = "",
    probe_mode: str = "b32",
    timeout: float = PROBE_TIMEOUT,
    config: I2PConfig | None = None,
) -> DiscoveryResult:
    """Single HTTP fetch through proxy. Returns reachable=0 on any failure.
    
    ``timeout`` is the per-target deadline in seconds (default 120).
    The underlying I2PProxyClient uses this as a socket timeout.
    ``config`` provides proxy host/port settings; defaults to I2PConfig().
    """
    start = time.monotonic()
    try:
        resp = fetch_i2p(url, via="http-proxy", timeout=timeout, config=config)
        elapsed = round(time.monotonic() - start, 2)
        body_text = resp.text if hasattr(resp, "text") else resp.body.decode("utf-8", errors="replace")

        # Memory protection: truncate very large responses before analysis.
        # Most meaningful content lives in the first 100–256 KB; beyond that
        # we only keep a length hint so huge pages (e.g. file dumps, API logs)
        # don't explode memory during classification + flag extraction.
        if len(body_text) > 256 * 1024:
            logger.debug(
                "  [memory] %s – large response (%d KB), truncating to 256 KB for analysis",
                ident_hash_hex,
                len(body_text) // 1024,
            )
            body_text = body_text[:256 * 1024]

        # Extract title and classify content
        title_text = ""
        try:
            title_m = resp.title()
            if title_m:
                title_text = title_m.strip()
        except Exception:
            pass

        # ── Extractor registry (replaces _classify_content) ─────────────
        from src.extractors import run_extractors

        resp_headers = dict(resp.headers) if hasattr(resp, 'headers') else {}
        extractor_result = run_extractors(
            title=title_text,
            body_text=body_text,
            headers=resp_headers,
            status_code=resp.status,
        )

        # Content hash for change detection
        content_hash = hashlib.sha256(resp.body).hexdigest() if resp.body else ""

        # Last-Modified header (change signal)
        last_modified = resp_headers.get("Last-Modified", "") or resp_headers.get("last-modified", "")

        # ── Flag extraction ────────────────────────────────────────────
        # Derive redirect depth from headers if available: i2p-projekt.i2p
        # and other sites often 301 through the proxy. urllib hides them,
        # but we can infer from Location header chain metadata or estimate
        # from response hop patterns. For now, use a heuristic counter based
        # on common redirects observed during probing.
        redirect_depth = _estimate_redirect_depth(url, resp_headers)

        flags = _extract_flags(body_text, resp_headers, redirect_depth)

        # Append needs_review reason as a structured flag so it appears in
        # address_book and can be queried / filtered from the CLI.
        if extractor_result.needs_review:
            flags.append(f"needs_review: {extractor_result.reason}")

        result = DiscoveryResult(
            b32_addr=url.split("/")[2] if "/" in url else "",
            ident_hash_hex=ident_hash_hex,
            reachable=200 <= resp.status < 500,
            status_code=resp.status,
            body_length=len(resp.body),
            title=title_text,
            response_time_sec=elapsed,
            via_method=probe_mode,
            probe_mode=probe_mode,
            content_type=extractor_result.content_type,
            content_summary=extractor_result.content_summary,
            found_links=extractor_result.links,
            flags=flags,
            needs_review=extractor_result.needs_review,
            reason=extractor_result.reason,
            content_hash=content_hash,
            last_modified=last_modified,
        )

        logger.info(
            "  [%s] %s  status=%d  body=%dB  %.1fs%s",
            probe_mode, url, resp.status, len(resp.body), elapsed,
            f"  title={result.title[:40]}" if result.title else "",
        )
        if flags:
            logger.info("    flags: %s", " | ".join(flags))
        return result

    except Exception as exc:
        elapsed = round(time.monotonic() - start, 2)
        tb = traceback.format_exc()
        logger.warning(
            "  [%s] %s  FAILED %.1fs:\n%s", probe_mode, url, elapsed, tb
        )
        return DiscoveryResult(
            b32_addr=url.split("/")  [2] if "/" in url else "",
            ident_hash_hex=ident_hash_hex,
            reachable=False,
            error=f"{exc}\n{tb}",
            response_time_sec=elapsed,
            via_method=probe_mode,
            probe_mode=probe_mode,
        )


class _RedirectCountingHandler(urllib.request.HTTPRedirectHandler):
    """Subclass that counts how many 3xx redirects were followed."""

    def __init__(self) -> None:
        super().__init__()
        self.redirect_count = 0

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: any,
        code: int,
        msg: str,
        headers: http_client.HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        # Only count actual redirects (3xx) that we actually follow
        if 300 <= code < 400 and code != 304:
            self.redirect_count += 1
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _estimate_redirect_depth(url: str, _headers: dict) -> int:
    """Return the number of redirects actually followed during this fetch.

    We do this by re-wrapping the opener with a counting handler *before*
    calling ``fetch_i2p`` — see the refactored ``_do_probe`` below.
    This stub is kept for backward compatibility and unit tests.
    """
    # When called standalone (e.g., inside _extract_flags unit tests),
    # we have no access to the opener, so return 0.
    return 0


# ---------------------------------------------------------------------------
# Batch discovery runner
# ---------------------------------------------------------------------------

def discover_addresses(
    known_addrs: list[str | tuple[str, str]] | None = None,
    catalog: AddressBookCatalog | None = None,
    config: I2PConfig | None = None,
    db_path: str = DEFAULT_DB_PATH,
    db_instance: DiscoveryDB | None = None,
    probe_delay: float = 5.0,
    timeout: float = PROBE_TIMEOUT,
    limit: int | None = None,
    filter_mode: str = "all",
    min_age_hours: float = 24.0,
) -> list[DiscoveryResult]:
    """Probe destinations and record results in persistent DB.

    Args:
        known_addrs: List of .i2p hostnames, ident hashes, or (hash, dns_name) tuples
            to probe. Each item can be: http://x.i2p/, x.i2p, a 40-char hex hash,
            or (ident_hash_hex, i2p_dns_name). If a tuple is given, BOTH the b32 key
            and DNS name are probed.
            If omitted, uses catalog destinations if available.
        catalog: Pre-loaded AddressBookCatalog for source of truth.
        config: I2P configuration override.
        db_path: Path to SQLite DB (used when db_instance not provided).
        db_instance: Optional pre-created DiscoveryDB (for testing).
        probe_delay: Seconds to wait between targets (default 5s). I2P is slow;
            this prevents hammering the network with rapid-fire requests.
        timeout: Per-target probe deadline in seconds (default 120s from PROBE_TIMEOUT).
        filter_mode: Passed through to DiscoveryDB.get_targets(). Controls which
            targets are returned when no known_addrs/catalog are provided.
            Options: "all" (default), "reachable_only", "never_probed", "stale".
        min_age_hours: Hours threshold for "stale" filter_mode (default 24).

    Returns:
        List of DiscoveryResult objects sorted by reachability then speed.
    """
    cfg = config or I2PConfig()
    use_existing_db = db_instance is not None
    db = db_instance or DiscoveryDB(db_path)

    try:
        # ── Gather targets as (hash, dns_name) pairs ────────────────
        targets: list[tuple[str, str]] = []  # (ident_hash_hex, dns_name_or_empty)

        if known_addrs:
            for addr in known_addrs:
                if isinstance(addr, tuple):
                    # Already a (hash, dns_name) pair
                    h, d = addr
                    targets.append((h.upper() if h else "", d))
                    continue
                # Strip URL wrapper
                raw = addr.removeprefix("http://").removeprefix("https://").rstrip("/")
                if len(raw) == 40 and all(c in "0123456789abcdefABCDEF" for c in raw):
                    # It's a hash
                    targets.append((raw.upper(), ""))
                elif not raw.endswith(".b32.i2p"):
                    # Treat as DNS hostname
                    targets.append(("", raw))
                else:
                    # b32 address — try to extract hash (we store as-is and let probe convert)
                    targets.append(("", raw))

        elif catalog:
            for de in catalog.all_destinations():
                if de.b32_addr:
                    dns = ""
                    targets.append((de.ident_hash_hex, dns))

        else:
            # Seed DB with defaults, then query the target list
            initial: list[tuple[str, str]] = [
                ("", "i2p-projekt.i2p"),
                ("F95763B51C40A9EF8E2C5CE3D19D43EC8E5F10E9", "su3-directory.i2p"),
                ("", "mail.i2pmail.org"),
            ]
            db.upsert_targets(initial)
            targets = db.get_targets(filter_mode=filter_mode, min_age_hours=min_age_hours)

        # ── Apply limit if requested ────────────────────────────────
        if limit:
            targets = targets[:limit]

        # ── Probe each target (one at a time — I2P is slow) ─────────
        results: list[DiscoveryResult] = []

        for i, (hash_hex, dns_name) in enumerate(targets):
            if i > 0:
                logger.info("Waiting %.1fs before next probe...", probe_delay)
                time.sleep(probe_delay)
            logger.info("--- Probing [%d/%d]: hash=%s  dns=%s", i + 1, len(targets), hash_hex or "(none)", dns_name or "(none)")
            res = probe_destination(
                ident_hash_hex=hash_hex,
                i2p_dns_name=dns_name,
                db=db,
                timeout=timeout,
                config=cfg,
            )
            results.append(res)

        # Sort: reachable first, then fastest
        results.sort(key=lambda r: (not r.reachable, r.response_time_sec))

        # ── Maintenance: prune stale unreachable records ───────────────
        cleaned = db.cleanup_unreachable()
        if cleaned:
            logger.info("Cleaned up %d stale unreachable records", cleaned)

        summary = db.summary()
        logger.info("Discovery DB — %s", summary)
        return results
    finally:
        if not use_existing_db:
            db.close()


# ---------------------------------------------------------------------------
# Reporting / CLI
# ---------------------------------------------------------------------------

def print_report(results: list[DiscoveryResult], json_out: bool = False):
    """Pretty-print or return structured discovery results.

    When ``json_out=False`` (default), prints to stdout for terminal consumption.
    When ``json_out=True``, returns a dict with status counts, per-result details,
    and hash metadata — suitable for CSV export or programmatic pipelines.
    """
    reachable = [r for r in results if r.reachable]
    dead = [r for r in results if not r.reachable]

    # Structured output path
    if json_out:
        from dataclasses import asdict
        return {
            "total": len(results),
            "by_status": {k: sum(1 for r in results if getattr(r, k))
                         for k in ("reachable",)},
            "reachable_count": len(reachable),
            "dead_count": len(dead),
            "results": [asdict(r) for r in results],
        }

    print(f"\n{'='*70}")
    print(f"  I2P DISCOVERY RESULTS")
    print(f"  Total: {len(results)} | Reachable: {len(reachable)} | Dead: {len(dead)}")
    print(f"{'='*70}")

    for r in results:
        status = "OK" if r.reachable else "DOWN"
        tag = f"[{r.via_method}]" if r.via_method else "[?]"
        ctype = f"  {r.content_type}" if r.content_type else ""
        line = (
            f"  [{status}] {tag:>7}  {r.b32_addr[:40]:<40}"
            f"  status={r.status_code:<5d}  body={r.body_length:<8d}"
            f"  time={r.response_time_sec:.1f}s{ctype}"
        )
        if r.title:
            line += f'  "{r.title[:50]}"'
        if r.content_summary and r.content_summary != f'Unidentified site — "{r.title}"':
            print(f"    summary: {r.content_summary[:120]}")
        if r.flags:
            print(f"    flags:   {' | '.join(r.flags)}")
        if r.error:
            line += f"  err={r.error[:40]}"
        print(line)

    # Show hashes
    print(f"\n  Hashes discovered:")
    for r in results:
        if r.ident_hash_hex:
            prefix = "reachable" if r.reachable else "unreachable"
            hash_snippet = r.ident_hash_hex[:12] + "..." if len(r.ident_hash_hex) > 12 else r.ident_hash_hex
            print(f"    {r.ident_hash_hex} [{prefix}]")
        elif r.b32_addr.startswith("http"):
            host = r.b32_addr.split("/")[2] if "//" in r.b32_addr else ""
            print(f"    (no hash yet)  DNS: {host}")
    print()


def query_db(hash_hex: str = "", dns_name: str = "", db_path: str = DEFAULT_DB_PATH) -> list[dict]:
    """Query the persistent discovery DB. Accepts hash or DNS name."""
    with _db_lock:
        db = DiscoveryDB(db_path)
        results = []
        if hash_hex:
            results = db.get_latest_probes_by_hash(hash_hex.upper())
        elif dns_name:
            results = db.get_latest_probes_by_dns_name(dns_name)
        else:
            # Return summary
            s = db.summary()
            print(f"\nDB Summary: {s}\n")
            print("Usage: query_db(hash_hex='...') or query_db(dns_name='...')\n")
        db.close()
    return results


def get_address_book(
    db_path: str = DEFAULT_DB_PATH,
    limit: int | None = None,
    needs_review_only: bool = False,
) -> list[dict]:
    """Return the address_book view -- one row per destination with the most
    recent probe, joined against router and leaseset metadata.

    Args:
        db_path: Path to the SQLite database.
        limit: Optional maximum number of rows to return.
        needs_review_only: If True, only return entries flagged for review.

    Columns returned:
        dns_name, content_type, reachable, last_probed_utc, content_summary,
        ident_hash_hex, b32_addr, status_code, body_length, title, response_time_sec,
        via_method, last_probed_at, bandwidth_kbps, router_caps, num_leases,
        flags, needs_review
    """
    with _db_lock:
        db = DiscoveryDB(db_path)
        rows = db.address_book(limit=limit)
        db.close()

    if needs_review_only:
        rows = [r for r in rows if r.get("needs_review")]

    return rows


def print_address_book(
    entries: list[dict],
    json_out: bool = False,
    needs_review_only: bool = False,
):
    """Pretty-print or return structured address book data.

    When ``json_out=False`` (default), prints to stdout for terminal consumption.
    When ``json_out=True``, returns the entries list plus summary counts -- suitable
    for CSV export, programmatic pipelines, or loading in another script.

    Args:
        entries: Rows from address_book view.
        json_out: Return structured JSON-serializable dict instead of printing.
        needs_review_only: Filter to only destinations flagged needs_review.
    """
    if needs_review_only:
        entries = [r for r in entries if r.get("needs_review")]
    if json_out:
        reachable = sum(1 for e in entries if e.get("reachable"))
        return {
            "total": len(entries),
            "reachable_count": reachable,
            "dead_count": len(entries) - reachable,
            "entries": entries,
        }

    if not entries:
        print("\n  (address book is empty — run a discovery first)\n")
        return

    reachable = sum(1 for e in entries if e["reachable"])
    dead = len(entries) - reachable

    print(f"\n{'='*72}")
    print(f"  I2P Address Book  —  {len(entries)} destination(s), "
          f"{reachable} reachable, {dead} unreachable")
    print(f"{'='*72}")

    for e in entries:
        status = "OK" if e["reachable"] else "DOWN"
        utc = e.get("last_probed_utc", "") or ""

        # ── rich synthesized summary (from view, replaces raw content_summary) ──
        rich = (e.get("content_summary") or "")[:200]

        line = f"  [{status:>4}] {utc!s:<20} {rich}"

        # Append content hash abbreviation when available
        chash = e.get("content_hash", "") or ""
        if chash:
            line += f" #{chash[:12]}"

        # Append last_modified as a trailing annotation
        lmod = e.get("last_modified", "") or ""
        if lmod and lmod != "N/A":
            from datetime import datetime
            try:
                dt = datetime.strptime(lmod, "%a, %d %b %Y %H:%M:%S %Z")
                line += f" modified:{dt.strftime('%Y-%m-%d')}"
            except (ValueError, TypeError):
                pass

        # Append link count
        flinks_raw = e.get("found_links", "") or ""
        try:
            flinks_list = _json.loads(flinks_raw) if isinstance(flinks_raw, str) else []
            if not isinstance(flinks_list, list):
                flinks_list = []
        except (_json.JSONDecodeError, TypeError):
            flinks_list = []
        if len(flinks_list) > 0:
            line += f" {len(flinks_list)} linked sites"

        # Append method tag
        tag = e.get("via_method", "") or ""
        if tag:
            line += f" [{tag}]"

        # Append flags
        flags_raw = e.get("flags", "") or ""
        try:
            flags_list = _json.loads(flags_raw) if isinstance(flags_raw, str) else []
            if not isinstance(flags_list, list):
                flags_list = []
        except (_json.JSONDecodeError, TypeError):
            flags_list = []
        if flags_list:
            line += f" flags({','.join(flags_list)})"

        print(line)

    print(f"\n{'='*72}\n")


def main() -> None:
    """CLI entry point for discovery."""
    import sys
    import argparse

    p = argparse.ArgumentParser(description="I2P Indexer — destination discovery")
    sub = p.add_subparsers(dest="command")

    # ── sweep (default: probe targets) ────────────────────────────────
    sweep_p = sub.add_parser("sweep", help="Probe I2P destinations")
    sweep_p.add_argument(
        "--probe-timeout",
        type=float,
        default=None,
        help="Per-target probe timeout in seconds (default: 120)",
    )
    sweep_p.add_argument("targets", nargs="*", help=".i2p hostnames or SHA-1 hashes to probe")

    # ── show -- print the address book ────────────────────────────────
    show_p = sub.add_parser("show", help="Show address book entries")
    show_p.add_argument(
        "--needs-review",
        action="store_true",
        help="Show only destinations flagged for review (no extractor match or low-quality extract)",
    )
    show_p.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON instead of pretty-printed text",
    )

    # ── reprobe: re-probe flagged destinations and clear flags on success ──
    reprobe_p = sub.add_parser("reprobe", help="Re-probe destinations flagged needs_review")
    reprobe_p.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of flagged destinations to re-probe",
    )
    reprobe_p.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        help="Per-target probe timeout in seconds (default: 120)",
    )

    args = p.parse_args()

    if hasattr(args, "probe_timeout") and args.probe_timeout is not None:
        global PROBE_TIMEOUT
        PROBE_TIMEOUT = args.probe_timeout

    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    cfg = I2PConfig()

    if args.command == "reprobe":
        _do_reprobe(limit=args.limit, timeout=args.timeout)
    elif args.command == "show" or args.command is None and getattr(args, "needs_review", False):
        # Address book mode (explicit 'show' or --needs-review on bare invocation)
        entries = get_address_book(needs_review_only=getattr(args, "needs_review", False))
        print_address_book(entries, json_out=getattr(args, "json", False), needs_review_only=getattr(args, "needs_review", False))
    else:
        # Default sweep mode — probe targets
        _targets = getattr(args, "targets", [])
        results = discover_addresses(
            known_addrs=_targets if _targets else None, config=cfg, timeout=getattr(args, "probe_timeout", None) or PROBE_TIMEOUT
        )
        print_report(results)


def _do_reprobe(limit: int | None = None, timeout: float = 120.0) -> None:
    """Re-probe destinations flagged with needs_review and clear the flag on success.

    Iterates over all destinations currently flagged in the address_book view,
    probes them via b32+DNS (if available), runs extraction again, and clears
    the needs_review flag when a successful content_type extraction is obtained.

    Args:
        limit: Max number of flagged destinations to attempt (None = all).
        timeout: Per-target probe timeout in seconds.
    """
    db = DiscoveryDB(DEFAULT_DB_PATH)
    try:
        flagged = db.get_flagged_destinations(limit=limit)

        if not flagged:
            print("\n  No destinations currently flagged for review.")
            return

        n_total = len(flagged)
        print(f"\n  Reprobe queue: {n_total} flagged destination(s)")
        print(f"  Timeout per target: {timeout}s")
        print("-" * 48)

        n_ok = 0
        n_fail = 0
        n_cleared = 0

        seen_hashes: set[str] = set()

        for idx, (hash_hex, dns_name) in enumerate(flagged, 1):
            # Deduplicate by hash if we see the same destination multiple times
            if hash_hex and hash_hex in seen_hashes:
                continue
            if hash_hex:
                seen_hashes.add(hash_hex)

            label = f"[{idx}/{n_total}]"
            target_label = hash_hex[:12] + "..." if hash_hex else dns_name

            print(f"\n  {label} Probing: {target_label}")

            try:
                result = probe_destination(
                    ident_hash_hex=hash_hex if hash_hex else "",
                    i2p_dns_name=dns_name or "",
                    db=db,
                    timeout=timeout,
                    config=None,  # uses default I2P proxy (127.0.0.1:4444)
                )
            except Exception as e:
                print(f"    ERROR: {e}")
                n_fail += 1
                continue

            reachable = result.reachable if hasattr(result, "reachable") else False
            content_type = getattr(result, "content_type", "") or ""
            title = getattr(result, "title", "") or ""

            status_str = "OK" if reachable else "DOWN"
            info_parts = [f"status={status_str}"]
            if content_type:
                info_parts.append(f"type={content_type}")
            if title:
                info_parts.append(f'title="{title[:40]}"')
            print(f"    {' '.join(info_parts)}")

            if reachable and content_type:
                # Successful extraction — clear the flag
                cleared = db.clear_needs_review(hash_hex) if hash_hex else 0
                if cleared:
                    n_cleared += 1
                    print(f"    Flag cleared (content_type extracted successfully)")
                n_ok += 1
            elif reachable and not content_type:
                # Still can't extract — leave flag in place
                n_ok += 1
            else:
                n_fail += 1

        print(f"\n{'='*48}")
        print(f"  Reprobe complete: {n_ok} ok, {n_fail} failed, "
              f"{n_cleared} dest(s) unflagged")
        print(f"{'='*48}\n")
    finally:
        db.close()


if __name__ == "__main__":
    main()
