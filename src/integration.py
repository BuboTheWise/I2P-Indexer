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
import logging
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.addressbook import AddressBookCatalog, _hex_to_b32_addr
from src.config import I2PConfig
from src.i2p_proxy import ProxyBackend, fetch_i2p
from src.models import DestinationEntry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TAG_RE = re.compile(r"<[^>]+>")


def _truncate(text: str, max_len: int) -> str:
    """Cut text to a safe length for SQLite storage."""
    return text[:max_len] if len(text) > max_len else text


# Regular expression to find .i2p hostnames in HTML/link text
_I2P_LINK_RE = re.compile(
    r"[a-z0-9\-]+\.i2p(?:\b|[/\"'\s])",
    re.IGNORECASE,
)


def _extract_i2p_links(body_text: str) -> list[str]:
    """Return unique .i2p hostnames found in page body text."""
    return list({h.strip().lower() for h in _I2P_LINK_RE.findall(body_text[:32768])})


def _classify_content(
    title: str,
    body_text: str,
) -> tuple[str, str, list[str]]:
    """Heuristic content classification from title + stripped HTML.

    Returns (content_type_bucket, content_summary, linked_i2p_sites).
    This is intentionally a local, offline heuristic — no LLM required at probe time.
    Later passes can re-classify with an LLM if desired.
    """
    lower_title = title.lower()
    lower_body = body_text[:16384].lower()  # first 16KB is enough for heuristics

    # ── Bucket detection ──────────────────────────────────────────────
    type_keywords: list[tuple[str, list[str]]] = [
        ("forum", ["forum", "board", "thread", "post", "topic"]),
        ("wiki", ["wiki", "knowledge base", "mediawiki"]),
        ("blog", ["blog", "diary", "journal", "entries"]),
        ("file archive", ["mirror", "files", "download", "archive", "repository"]),
        ("marketplace", ["market", "store", "shop", "buy", "sell"]),
        ("news site", ["news", "headlines", "updates", "press"]),
        ("mail server", ["mail", "email", "postfix", "smtp"]),
        ("chat room", ["chat", "irc", "messaging"]),
        ("search engine", ["search", "find", "index", "discover"]),
    ]

    content_type = ""
    for bucket, keywords in type_keywords:
        if any(kw in lower_title or kw in lower_body for kw in keywords):
            content_type = bucket
            break

    # ── Summary generation ────────────────────────────────────────────
    plain = _TAG_RE.sub(" ", body_text)
    words = " ".join(plain.split()).strip()[:200]

    # ── Link extraction ───────────────────────────────────────────────
    linked_sites = _extract_i2p_links(body_text)

    if content_type:
        summary = f"{content_type.title()} — «{title}»"
    else:
        summary = f"Unidentified site — «{title}»"

    # Append link info to summary if found
    if linked_sites:
        summary += f" [found {len(linked_sites)} linked i2p site(s)]"

    return content_type, summary, linked_sites


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class DiscoveryResult:
    """Result of probing a single destination."""

    b32_addr: str
    ident_hash_hex: str
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
    found_links: list[str] | None = field(default_factory=list)
    content_hash: str = ""     # SHA-256 of body for change detection
    last_modified: str = ""    # HTTP Last-Modified header value


# ---------------------------------------------------------------------------
# Persistent discovery database
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH = os.path.join(os.getcwd(), "indexer.db")


class DiscoveryDB:
    """SQLite store for probe results and full addressbook records."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self._path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_db()

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

    def record_lease_set(
        self,
        ident_hash_hex: str,
        store_type: int = 0,
        num_leases: int = 0,
        i2p_dns_name: str = "",
        source: str = "probe",
    ) -> None:
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
        error_msg: str = "",
    ) -> int:
        """Record one probe attempt. Returns the new row id."""
        cur = self._conn.cursor()
        now = datetime.now(timezone.utc).timestamp()
        import json as _json

        cur.execute(
            """INSERT INTO discoveries
               (ident_hash_hex, b32_addr, i2p_dns_name, probe_mode, reachable,
                status_code, body_length, title, response_time, via_method,
                content_type, content_summary, content_hash, last_modified,
                found_links, error_msg, probed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ident_hash_hex, b32_addr, i2p_dns_name, probe_mode, int(reachable),
             status_code, body_length, title, response_time, via_method,
             content_type, _truncate(content_summary, 4096), content_hash,
             last_modified, _json.dumps(found_links or []), error_msg, now),
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

    def get_all_hashes(self) -> list[str]:
        """Get unique ident hashes discovered so far."""
        cur = self._conn.cursor()
        cur.execute("SELECT DISTINCT ident_hash_hex FROM discoveries")
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

    def address_book(self) -> list[dict]:
        """Return the 'address book' view: one row per destination showing the
        most recent probe result joined with router/leaseset metadata.

        Columns: dns_name, content_type, reachable, last_probed_utc, content_summary,
        ident_hash_hex, b32_addr, status_code, body_length, title, response_time_sec,
        via_method, last_probed_at, bandwidth_kbps, router_caps, num_leases.
        """
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM address_book ORDER BY dns_name ASC")
        cols = [desc[0] for desc in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def upsert_targets(self, targets: list[tuple[str, str]]) -> int:
        """Upsert target destinations. Tuple is (ident_hash_hex, i2p_dns_name)."""
        cur = self._conn.cursor()
        n = 0
        for h, d in targets:
            b32 = _hex_to_b32_addr(h) if len(h) == 40 else ""
            cur.execute(
                "INSERT OR REPLACE INTO targets "
                "(ident_hash_hex, b32_addr, i2p_dns_name) VALUES (?, ?, ?)",
                (h, b32, d or ""),
            )
            n += 1
        self._conn.commit()
        return n

    def get_targets(self) -> list[tuple[str, str]]:
        """Return the target queue as (hash_hex, dns_name) tuples."""
        cur = self._conn.cursor()
        cur.execute("SELECT ident_hash_hex, i2p_dns_name FROM targets")
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
        self._conn.close()


# ---------------------------------------------------------------------------
# Probe logic — try b32 key AND dns name
# ---------------------------------------------------------------------------

def probe_destination(
    ident_hash_hex: str,
    i2p_dns_name: str = "",
    db: DiscoveryDB | None = None,
) -> DiscoveryResult:
    """Probe a single destination by BOTH its b32 key address and .i2p DNS name.

    Returns the best result (most data from fastest successful probe).
    If a DB is provided, records both attempts.
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
                error_msg=res_b32.error,
            )

    # ── Attempt 2: Try .i2p DNS name if available (may provide more info)
    if i2p_dns_name and not i2p_dns_name.endswith(".b32.i2p"):
        logger.info("Probing http://%s/  (.i2p DNS)", i2p_dns_name)
        res_dns = _do_probe(
            url=f"http://{i2p_dns_name}/",
            ident_hash_hex=ident_hash_hex,
            i2p_dns_name=i2p_dns_name,
            probe_mode="dns",
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
) -> DiscoveryResult:
    """Single HTTP fetch through proxy. Returns reachable=0 on any failure."""
    start = time.monotonic()
    try:
        resp = fetch_i2p(url, via="http-proxy")
        elapsed = round(time.monotonic() - start, 2)
        body_text = resp.text if hasattr(resp, "text") else resp.body.decode("utf-8", errors="replace")

        # Extract title and classify content
        title_text = ""
        try:
            title_m = resp.title()
            if title_m:
                title_text = title_m.strip()
        except Exception:
            pass

        c_type, c_summary, linked_sites = _classify_content(title_text, body_text)

        # Content hash for change detection
        content_hash = hashlib.sha256(resp.body).hexdigest() if resp.body else ""

        # Last-Modified header (change signal)
        last_modified = resp.headers.get("Last-Modified", "")

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
            content_type=c_type,
            content_summary=c_summary,
            found_links=linked_sites,
        )

        # Attach extra metadata
        result.content_hash = content_hash
        result.last_modified = last_modified

        logger.info(
            "  [%s] %s  status=%d  body=%dB  %.1fs%s",
            probe_mode, url, resp.status, len(resp.body), elapsed,
            f"  title={result.title[:40]}" if result.title else "",
        )
        return result

    except Exception as exc:
        elapsed = round(time.monotonic() - start, 2)
        logger.warning("  [%s] %s  FAILED %.1fs: %s", probe_mode, url, elapsed, exc)
        return DiscoveryResult(
            b32_addr=url.split("/")  [2] if "/" in url else "",
            ident_hash_hex=ident_hash_hex,
            reachable=False,
            error=f"{exc}",
            response_time_sec=elapsed,
            via_method=probe_mode,
            probe_mode=probe_mode,
        )


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

    Returns:
        List of DiscoveryResult objects sorted by reachability then speed.
    """
    cfg = config or I2PConfig()
    use_existing_db = db_instance is not None
    db = db_instance or DiscoveryDB(db_path)

    # ── Gather targets as (hash, dns_name) pairs ──────────────────────
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
        targets = db.get_targets()

    # ── Probe each target (one at a time — I2P is slow) ───────────────
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
        )
        results.append(res)

    # Sort: reachable first, then fastest
    results.sort(key=lambda r: (not r.reachable, r.response_time_sec))
    summary = db.summary()
    logger.info("Discovery DB — %s", summary)
    db.close()
    return results


# ---------------------------------------------------------------------------
# Reporting / CLI
# ---------------------------------------------------------------------------

def print_report(results: list[DiscoveryResult]) -> None:
    """Pretty-print discovery results to stdout."""
    reachable = [r for r in results if r.reachable]
    dead = [r for r in results if not r.reachable]

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


def get_address_book(db_path: str = DEFAULT_DB_PATH) -> list[dict]:
    """Return the address_book view — one row per destination with the most
    recent probe, joined against router and leaseset metadata.

    Columns returned:
        dns_name, content_type, reachable, last_probed_utc, content_summary,
        ident_hash_hex, b32_addr, status_code, body_length, title, response_time_sec,
        via_method, last_probed_at, bandwidth_kbps, router_caps, num_leases
    """
    db = DiscoveryDB(db_path)
    rows = db.address_book()
    db.close()
    return rows


def print_address_book(entries: list[dict]) -> None:
    """Pretty-print the address book view to a human-readable table."""
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
        ctype = e.get("content_type", "") or ""
        utc = e.get("last_probed_utc", "") or ""
        summary = (e.get("content_summary", "") or "")[:100]

        dns = e.get("dns_name", "") or e.get("b32_addr", "")

        ctype_tag = f" @{ctype}" if ctype else "  unknown"
        line = f"  [{status:>4}] {ctype_tag:<15} {utc!s:<20} {summary}"

        title = (e.get("title", "") or "")[:60]
        tag = e.get("via_method", "") or "?"
        bw = f" {e['bandwidth_kbps']}kbps" if (e.get("bandwidth_kbps") or 0) > 0 else ""

        extras: list[str] = []
        if dns and dns != summary[:len(dns)]:
            extras.append(dns)
        if title:
            extras.append(f'"{title}"')
        if tag:
            extras.append(f"[{tag}]")
        if bw:
            extras.append(bw)
        if extras:
            line += "  " + " ".join(extras)

        print(line)

    print(f"\n{'='*72}\n")


def main() -> None:
    """CLI entry point for discovery."""
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    cfg = I2PConfig()

    targets: list[str | tuple[str, str]] = []
    if len(sys.argv) > 1:
        targets = sys.argv[1:]  # type: ignore[assignment]
    else:
        # Use well-known defaults
        pass

    results = discover_addresses(known_addrs=targets or None, config=cfg)
    print_report(results)


if __name__ == "__main__":
    main()
