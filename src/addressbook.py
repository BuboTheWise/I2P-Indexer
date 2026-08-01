"""AddressBook catalog — scan netdb, parse .rtr/.ls64, query routers."""
from __future__ import annotations

import base64
import hashlib
import html as htmllib
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.config import I2PConfig
from src.ls64_parser import parse_ls64_file
from src.models import (
    CAP_FLOODFILL,
    DestinationEntry,
    LeaseSetInfo,
    RouterInfo,
)
from src.rtr_parser import parse_rtr_file

logger = logging.getLogger(__name__)


class AddressBookCatalog:
    """Scan a netdb directory for .rtr / .ls64 files and provide queries."""

    def __init__(
        self,
        netdb_dir: Optional[str | Path] = None,
        config: Optional[I2PConfig] = None,
        db_path: Optional[str] = ":memory:",
    ) -> None:
        self._config = config or I2PConfig()
        self._netdb_dir: Optional[Path] = Path(netdb_dir) if netdb_dir else None
        self._routers: dict[str, RouterInfo] = {}
        self._leasesets: dict[str, LeaseSetInfo] = {}

        # SQLite backing store
        self._conn = sqlite3.connect(db_path)
        self._init_db()

    def _init_db(self) -> None:
        cur = self._conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS routers (
                ident_hash_hex TEXT PRIMARY KEY,
                key_type       INTEGER,
                version        INTEGER DEFAULT 0,
                bandwidth_kbps INTEGER DEFAULT 0,
                options_mask   INTEGER DEFAULT 0,
                caps           TEXT    DEFAULT '',
                published      INTEGER DEFAULT 0,
                file_size      INTEGER DEFAULT 0,
                updated_at     REAL    DEFAULT (strftime('%s','now'))
            );
            CREATE TABLE IF NOT EXISTS transports (
                ident_hash_hex TEXT REFERENCES routers(ident_hash_hex),
                ip           TEXT,
                port         INTEGER,
                protocol     TEXT,
                published    INTEGER DEFAULT 1,
                created_at   REAL   DEFAULT 0.0
            );
            CREATE TABLE IF NOT EXISTS leasesets (
                ident_hash_hex  TEXT PRIMARY KEY,
                store_type      INTEGER,
                num_leases      INTEGER DEFAULT 0,
                options_mask    INTEGER DEFAULT 0,
                leases_v1_count INTEGER DEFAULT 0,
                created_at      REAL    DEFAULT 0.0,
                file_size       INTEGER DEFAULT 0,
                updated_at      REAL   DEFAULT (strftime('%s','now'))
            );
            """
        )
        self._conn.commit()

    # ── loading ────────────────────────────────────────────────────

    def load(self) -> int:
        """Scan netdb directory and parse all .rtr / .ls64 files.

        Falls back to webconsole scraping if no files found.
        Returns total entries loaded.
        """
        count = 0

        if self._netdb_dir and self._netdb_dir.is_dir():
            count = self._scan_netdb()

        if count == 0:
            logger.info("No .rtr/.ls64 files found — trying webconsole fallback")
            count = self._scrape_webconsole()

        # Persist to SQLite
        self._sync_db()
        return count

    def _scan_netdb(self) -> int:
        """Walk netdb dir, parse every .rtr and .ls64."""
        ndir = self._netdb_dir
        assert ndir is not None
        rtr_files = sorted(ndir.glob("*.rtr"))
        ls_files = sorted(ndir.glob("*.ls64"))

        for f in rtr_files:
            ri = parse_rtr_file(f)
            if ri and ri.ident_hash_hex != "0" * 40:
                self._routers[ri.ident_hash_hex] = ri

        for f in ls_files:
            li = parse_ls64_file(f)
            if li and li.ident_hash_hex != "0" * 40:
                self._leasesets[li.ident_hash_hex] = li

        return len(self._routers) + len(self._leasesets)

    # ── webconsole fallback ────────────────────────────────────────

    def _scrape_webconsole(self) -> int:
        """Scrape Java I2P webconsole for router data.

        The /peers page loads its peer table via AJAX to /xhr1.jsp, which means
        a plain GET only returns the sidebar navigation frame with no peer rows.
        We fall back to parsing whatever static content *is* present (router summary
        in the sidebar) and trying the direct XHR endpoint.

        NOTE: POST actions to the webconsole require a CSRF nonce, so we can't
        do anything that needs form submission.  GET-only data extraction is our
        limit without browser automation.
        """
        import urllib.request
        import re

        count = 0

        # Try the XHR endpoint first — it may return peer table HTML without CSRF
        count += self._scrape_xhr_peers()

        if count == 0:
            # Parse whatever static content is on the /peers page sidebar
            count += self._scrape_static_sidebar()

        if count == 0:
            # Try /netdb as secondary fallback
            count += self._scrape_netdb_page()

        return count

    def _scrape_xhr_peers(self) -> int:
        """Try the AJAX endpoint that powers the peers table."""
        import urllib.request
        import re

        xhr_url = f"http://{self._config.webconsole_host}:{self._config.webconsole_port}/xhr1.jsp?requestURI=/peers.jsp"
        count = 0

        try:
            req = urllib.request.Request(xhr_url, headers={"User-Agent": "I2P-Indexer/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="replace")

            # The XHR response still returns the sidebar + any table data
            # Look for router hash patterns in links or text
            hashes = self._extract_hashes_from_body(body)
            for hx in hashes:
                if hx not in self._routers:
                    self._routers[hx] = RouterInfo(
                        ident_hash_hex=hx,
                        key_type=1,
                        caps="scraped",
                    )
                    count += 1

        except Exception as exc:
            logger.debug("XHR peers scrape failed: %s", exc)

        return count

    def _scrape_static_sidebar(self) -> int:
        """Parse the /peers page static content for any hash data.

        Most router data lives in the AJAX-loaded table, but the sidebar may
        contain links to individual router pages with hashes.
        """
        import urllib.request

        peers_url = f"http://{self._config.webconsole_host}:{self._config.webconsole_port}/peers"
        count = 0

        try:
            req = urllib.request.Request(peers_url, headers={"User-Agent": "I2P-Indexer/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="replace")

            hashes = self._extract_hashes_from_body(body)
            for hx in hashes:
                if hx not in self._routers:
                    self._routers[hx] = RouterInfo(
                        ident_hash_hex=hx,
                        key_type=1,
                        caps="sidebar",
                    )
                    count += 1

        except Exception as exc:
            logger.warning("Webconsole scrape failed: %s", exc)

        return count

    @staticmethod
    def _extract_hashes_from_body(body: str) -> set[str]:
        """Extract 40-char hex hashes from HTML body text."""
        import re
        hashes: set[str] = set()

        # Find 40-char hex strings (router identity hashes)
        for m in re.finditer(r'\b([0-9a-fA-F]{40})\b', body):
            hx = m.group(1).upper()
            if hx != "0" * 40:
                hashes.add(hx)

        # Find base64-encoded filenames that decode to SHA-1 hashes
        for m in re.finditer(r'(?:href|filename)[="\'>\s]+([A-Za-z0-9+/=_-]{25,35})(?:\.rtr|\.ls64)', body):
            raw = _b64tohex(m.group(1))
            if raw and len(raw) == 40:
                hashes.add(raw.upper())

        return hashes

    def _scrape_netdb_page(self) -> int:
        """Parse the /netdb HTML listing page."""
        import urllib.request

        netdb_url = f"http://{self._config.webconsole_host}:{self._config.webconsole_port}/netdb"
        count = 0

        try:
            req = urllib.request.Request(netdb_url, headers={"User-Agent": "I2P-Indexer/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="replace")

            # Look for .rtr / .ls64 links
            import re
            links = re.findall(r'href=["\']?([A-Za-z0-9+/=_-]+)\.(?:rtr|ls64)', body)
            seen: set[str] = set()
            for link in links:
                bname = Path(link).stem
                hex_h = _b64tohex(bname) or hashlib.sha1(link.encode()).hexdigest().upper()
                if len(hex_h) == 40 and hex_h not in seen:
                    seen.add(hex_h)
                    self._routers[hex_h] = RouterInfo(
                        ident_hash_hex=hex_h,
                        key_type=1,
                        caps="R",
                        file_size=0,
                    )
                    count += 1
        except Exception as exc:
            logger.warning("NetDB page scrape failed: %s", exc)

        return count

    def _extract_hash_from_cells(self, cell_html: str) -> Optional[str]:
        """Pull a 40-hex hash or b64 name from an HTML td."""
        import re

        # Direct hex hash
        m = re.search(r"[0-9a-fA-F]{20,40}\b", cell_html)
        if m and len(m.group(0)) == 40:
            return m.group(0)

        # Base64-encoded router identity link
        link_m = re.search(r'href="([^"]+)"', cell_html)
        if link_m:
            raw = _b64tohex(Path(link_m.group(1)).stem)
            if raw and len(raw) == 40:
                return raw

        # Last resort: any sequence of b64 chars
        b64_m = re.search(r'[A-Za-z0-9+/=]{25,30}', htmllib.unescape(cell_html))
        if b64_m:
            raw = _b64tohex(b64_m.group(0))
            if raw and len(raw) == 40:
                return raw

        return None

    @staticmethod
    def _parse_caps_row(caps_text: str, bw_text: str) -> tuple[str, int, bool]:
        """Parse capability row from webconsole HTML. Returns (caps, bw, published)."""
        caps = ""
        bw = 0
        published = True

        # BW text often looks like "256 KBps" or "MBits"
        import re
        bw_m = re.search(r"(\d+)", htmllib.unescape(bw_text))
        if bw_m:
            bw = int(bw_m.group(1))

        caps_clean = re.sub(r"<[^>]+>", "", caps_text)
        for ch in caps_clean:
            if ch.isalpha() and ch.lower() != "x":
                caps += ch

        published = True
        return caps, bw, published

    # ── sync to SQLite ────────────────────────────────────────────

    def _sync_db(self) -> None:
        cur = self._conn.cursor()
        now = datetime.now(timezone.utc).timestamp()

        for ri in self._routers.values():
            cur.execute(
                "INSERT OR REPLACE INTO routers VALUES (?,?,?,?,?,?,?,?,?)",
                (ri.ident_hash_hex, ri.key_type, ri.version, ri.bandwidth_kbps,
                 ri.options_mask, ri.caps, int(ri.published), ri.file_size, now),
            )
            # Clear old transports
            cur.execute("DELETE FROM transports WHERE ident_hash_hex=?", (ri.ident_hash_hex,))
            for t in ri.transports:
                cur.execute(
                    "INSERT INTO transports VALUES (?,?,?,?,?,?)",
                    (ri.ident_hash_hex, t.ip, t.port, t.protocol,
                     int(t.published), t.created_at),
                )

        for li in self._leasesets.values():
            cur.execute(
                "INSERT OR REPLACE INTO leasesets VALUES (?,?,?,?,?,?,?,?)",
                (li.ident_hash_hex, li.store_type, li.num_leases, li.options_mask,
                 li.leases_v1_count, li.created_at, li.file_size, now),
            )

        self._conn.commit()

    # ── query API ──────────────────────────────────────────────────

    def get_by_hash(self, hash_hex: str) -> tuple[Optional[RouterInfo], Optional[LeaseSetInfo]]:
        """Look up a destination by its 40-hex ident hash."""
        return (self._routers.get(hash_hex), self._leasesets.get(hash_hex))

    def all_routers(self) -> list[RouterInfo]:
        """Return all parsed router entries."""
        return sorted(self._routers.values(), key=lambda r: r.bandwidth_kbps, reverse=True)

    def all_destinations(self) -> list[DestinationEntry]:
        """Merge routers + leasesets into DestinationEntry objects."""
        all_hashes = set(self._routers.keys()) | set(self._leasesets.keys())
        entries: list[DestinationEntry] = []

        for hx in sorted(all_hashes):
            ri = self._routers.get(hx)
            li = self._leasesets.get(hx)
            b32 = _hex_to_b32_addr(hx, 20) if len(hx) == 40 else ""

            de = DestinationEntry(
                ident_hash_hex=hx,
                b32_addr=b32,
                is_router=ri is not None,
                routers_known=int(ri is not None),
                leasesets_known=int(li is not None),
            )
            entries.append(de)

        return entries

    def floodfill_only(self) -> list[RouterInfo]:
        """Return only routers with the 'f' (floodfill) capability."""
        return [r for r in self._routers.values() if r.is_floodfill]

    def stats(self) -> dict[str, object]:
        """Summary statistics about the current catalog."""
        n_routers = len(self._routers)
        n_ls = len(self._leasesets)
        floodfills = sum(1 for r in self._routers.values() if r.is_floodfill)

        bw_vals = [r.bandwidth_kbps for r in self._routers.values() if r.bandwidth_kbps > 0]
        avg_bw = int(sum(bw_vals) / len(bw_vals)) if bw_vals else 0
        max_bw = max(bw_vals) if bw_vals else 0

        return {
            "total_routers": n_routers,
            "total_leasesets": n_ls,
            "floodfill_count": floodfills,
            "avg_bandwidth_kbps": avg_bw,
            "max_bandwidth_kbps": max_bw,
            "unique_destinations": len(set(self._routers) | set(self._leasesets)),
        }

    def summary(self) -> str:
        """Human-readable one-paragraph summary."""
        s = self.stats()
        return (
            f"AddressBook: {s['total_routers']} routers, {s['total_leasesets']} lease sets, "
            f"{s['floodfill_count']} floodfills, {s['unique_destinations']} unique destinations. "
            f"Avg BW {s['avg_bandwidth_kbps']} KBps, max {s['max_bandwidth_kbps']} KBps."
        )

    def close(self) -> None:
        self._conn.close()


# ── helpers ────────────────────────────────────────────────────────

def _hex_to_b32_addr(hash_hex: str, hash_len: int = 20) -> str:
    """Convert a 40-char hex hash to a base32 .b32.i2p address."""
    raw = bytes.fromhex(hash_hex)[:hash_len]
    b32 = base64.b32encode(raw).decode().lower()
    return f"{b32}.b32.i2p"


def _b64tohex(b64name: str) -> Optional[str]:
    """Decode base64 filename stem to 40-hex."""
    if not b64name:
        return None
    try:
        padded = b64name + "=" * (-len(b64name) % 4)
        raw = base64.b64decode(padded, altchars=b"-_")
        if len(raw) == 20:
            return raw.hex()
    except Exception:
        pass
    try:
        padded = b64name + "=" * (-len(b64name) % 4)
        raw = base64.urlsafe_b64decode(padded)
        if len(raw) == 20:
            return raw.hex()
    except Exception:
        pass
    return None
