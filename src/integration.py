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

from src.addressbook import AddressBookCatalog, _hex_to_b32_addr
from src.config import I2PConfig
from src.i2p_proxy import ProxyBackend, fetch_i2p, probe_tcp_banner, classify_service
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


# ---------------------------------------------------------------------------
# Simhash (meta-characteristic) near-duplicate detection
# ---------------------------------------------------------------------------
# Standard 64-bit simhash over word tokens (Manning, Raghavan & Schütze).
# Two documents with similar content produce 64-bit fingerprints whose Hamming
# distance is small (typical threshold: ≤2 or ≤3 bits for 64-bit hashes).
# We keep the discoveries table lean by storing one simhash per ident in a
# separate ``simhash_index`` table and answering "is this a near-dup of
# anything else?" with a Hamming-distance scan over that table.

#: Minimum Hamming distance accepted by default (≤3 bits for a 64-bit hash
#: is a common recall/precision sweet spot; 0 = exact match).
DEFAULT_SIMHASH_MAX_HAMMING: int = 3

_WORD_TOKEN_RE = re.compile(r"[a-zA-Z0-9]+(?:['\-][a-zA-Z]+)*", re.UNICODE)


def _tokenize_simhash(text: str) -> list[str]:
    """Lowercase word tokens for simhash input.

    Handles English contractions and hyphenated compounds, strips HTML tags
    first so tag names (``b``, ``p``) do not become tokens and pollute the
    meta-characteristic, and otherwise splits on any non-alphanumeric
    (space, punctuation, etc.).
    """
    if not text:
        return []
    cleaned = re.sub(r"<[^>]+>", " ", text)
    return _WORD_TOKEN_RE.findall(cleaned.lower())


def compute_simhash(content_text: str) -> int:
    """Compute a 64-bit simhash (meta-characteristic) over word tokens.

    Deterministic: same text → same 64-bit int. Uses Python's standard
    ``hashlib.md5`` for the per-token 64-bit fingerprint (stable across
    processes and Python hash randomization, unlike builtin ``hash()``).

    Returns 0 for empty / fully-non-tokenizable input (defensive: the
    Hamming scan treats 0 as a real hash, but two empty texts trivially
    match — which is the desired behaviour).
    """
    tokens = _tokenize_simhash(content_text)
    if not tokens:
        return 0

    # 64 independent accumulators for the sign-bit sum, one per bit position.
    # v[i] = Σ sign_i(token) for each bit position i.  Then the final hash is
    # 1 where v[i] > 0, else 0 — i.e. the majority-vote "meta-characteristic".
    v = [0] * 64
    for tok in tokens:
        # 64-bit per-token fingerprint, stable across Python sessions.
        h = int.from_bytes(hashlib.md5(tok.encode("utf-8")).digest()[:8], "little")
        for i in range(64):
            if (h >> i) & 1:
                v[i] += 1
            else:
                v[i] -= 1
    out = 0
    for i in range(64):
        if v[i] > 0:
            out |= (1 << i)
    return out


def hamming_distance(a: int, b: int) -> int:
    """Number of differing bits between two 64-bit hashes."""
    # bin(x ^ y).count("1") is O(bits) and portable — no platform-specific
    # popcount required.  For a 64-bit scalar this is trivially fast.
    return bin(a ^ b).count("1")


# ---------------------------------------------------------------------------
# Router cache helpers — fetch destination blobs from Java daemon's internal DNS
# ---------------------------------------------------------------------------

def _fetch_susi_dest_for_hash(
    ident_hash_hex: str,
    config: I2PConfig | None = None,
) -> str | None:
    """Look up a destination blob in the local router's SUSI DNS cache.

    After probing a .i2p address through the HTTP proxy, the Java daemon has
    already resolved and cached the full destination data internally.  This
    function queries ``/susidns/export?book=router`` on port 7657 and extracts
    the base64 blob matching *ident_hash_hex*.

    Returns the original I2P base64 string (with ``~`` padding) or ``None``
    when the cache has no entry, the webconsole is unreachable, or a timeout
    occurs.  Never raises — failures are logged silently so this can be used
    as a best-effort post-probe enrichment step without risking the probe
    pipeline.

    Args:
        ident_hash_hex: 40-char hex identity hash to look up.
        config: Optional I2PConfig override; defaults to standard config.
    """
    cfg = config or I2PConfig()
    webconsole_port = getattr(cfg, 'webconsole_port', 7657)

    try:
        import socket
        sock = socket.create_connection(('127.0.0.1', webconsole_port), timeout=3)
        sock.sendall(b"GET /susidns/export?book=router HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        response = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            response += chunk
        sock.close()

        # Split headers/body at double newline
        body_part = response.split(b"\r\n\r\n", 1)[-1].decode("utf-8", errors="replace")
    except Exception:
        return None

    # Parse the export and look for our hash (reuse parse_susi_export logic inline)
    target_hash = ident_hash_hex.upper()
    current_b32_raw = ""

    for line in body_part.split("\n"):
        line = line.rstrip()
        if not line.strip():
            continue
        if line.startswith("#"):
            comment_text = line[1:].strip()
            b32_match = re.match(r"^(.+?):\s+(.+?)\.b32\.i2p", comment_text)
            if b32_match:
                current_b32_raw = b32_match.group(2).strip()
            continue
        if "=" in line:
            _name, dest_data = line.split("=", 1)
            dns_name = _name.strip()
            if not dest_data.strip():
                continue
            # Extract base64 blob (before signature marker)
            if "#!sig=" in dest_data:
                dest_b64 = dest_data.split("#!sig=", 1)[0].strip()
            else:
                dest_b64 = dest_data.strip()

            # Try to decode and compute hash
            dest_std = dest_b64.replace("~", "_").replace("-", "+").replace("_", "/")
            pad_needed = len(dest_std) % 4
            if pad_needed:
                dest_std += "=" * (4 - pad_needed)
            try:
                raw = base64.b64decode(dest_std)
                entry_hash = raw[:20].hex().upper()
                if entry_hash == target_hash:
                    return dest_b64
            except Exception:
                continue

    return None


def parse_susi_export(path: str | Path) -> list[dict]:
    """Parse a SUSI DNS address book export file (e.g. from /susidns/export?book=router).

    Format per line group:
        # DNS_NAME: comment-with-b32-address.b32.i2p
        DNS_NAME=base64_destination_data   [#!sig=...]

    Returns list of dicts with keys: i2p_dns_name, ident_hash_hex, b32_raw, dest_data_len, dest_b64.
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
                    # Preserve the original I2P base64 blob for susidns export.
                    # This is the format used by /susidns/export: line.split('=',1)[1]
                    # before any normalization — identical to what the router expects.
                    'dest_b64': dest_b64,
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
) -> list[dict]:
    """Analyse page content + response headers and emit structured flag dicts.

    Each flag is a ``{"type": "...", "value": "..."}`` dict matching the schema
    in DATABASE_SCHEMA.md. Four canonical types plus extensible extras:

      - robots_txt       — robots policy signals (disallow_all, partial_block)
      - tech_stack       — web framework / CMS / server fingerprints
      - contact_signal   — PGP keys, email addresses, Tor contact forms, social links
      - proxy_indicator  — CDN/proxy/reverse-proxy headers (cloudflare, akamai, ...)

    Additional types "forum_software" and "redirect_chain" are emitted when
    relevant evidence is found.

    Args:
        body_text: Full HTML/body text from the probe response.
        resp_headers: HTTP response headers dict (may be empty/None).
        redirect_depth: Number of redirects followed (>0 means a chain existed).

    Returns:
        List of flag dicts, e.g. ``[{"type": "robots_txt", "value": "disallow_all"}, ...]``.
    """
    if resp_headers is None:
        resp_headers = {}

    flags: list[dict] = []
    body_slice = body_text[:32768]  # first 32 KB for heuristics
    lower_body = body_slice.lower()

    # ── 1. robots_txt — disallow policy ───────────────────────────────
    _robots_re = re.compile(
        r'user-agent\s*:\s*\*\s*\n\s*disallow\s*:\s*/\s*',
        re.IGNORECASE,
    )
    if _robots_re.search(lower_body):
        flags.append({"type": "robots_txt", "value": "disallow_all"})
    elif "user-agent" in lower_body and "disallow:" in lower_body:
        # Some paths are blocked but not the entire root
        flags.append({"type": "robots_txt", "value": "partial_block"})

    # ── 2. tech_stack — server, framework, CMS fingerprints ───────────
    detected_techs: list[str] = []

    # Server header (case-insensitive lookup)
    srv = ""
    for hdr_key in ("Server", "server"):
        srv = resp_headers.get(hdr_key, "")
        if srv:
            break
    if srv:
        detected_techs.append(srv)

    # X-Powered-By header (case-insensitive lookup)
    xp = ""
    for hdr_key in ("X-Powered-By", "x-powered-by"):
        xp = resp_headers.get(hdr_key, "")
        if xp:
            break
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
    gen_match = re.search(
        r'<meta[^>]+name=["\']?generator["\']?\s+content=["\']([^"\']+)[ "\'"]',
        body_slice, re.IGNORECASE
    )
    if gen_match:
        gen_value = gen_match.group(1).strip()
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
            if re.search(pat, body_slice, re.IGNORECASE):
                detected_techs.append(cms)
                break  # one match per CMS is enough

    if detected_techs:
        flags.append({"type": "tech_stack", "value": ", ".join(detected_techs[:5])})

    # ── 3. contact_signal — PGP, email, Tor form, social links ────────
    _email_re = re.compile(
        r'[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z]{2,}',
        re.IGNORECASE,
    )
    found_emails = _email_re.findall(body_slice)
    if found_emails:
        flags.append({
            "type": "contact_signal",
            "value": f"email_address_in_page ({len(found_emails)} addr(s))",
        })

    # PGP/PGP key detection
    _pgp_patterns = [
        r'<[^>]+content=["\']application/pgp-keys["\']',
        r'-----BEGIN PGP PUBLIC KEY BLOCK-----',
        r'--begin pgp public key block--',
        r'armour.*public.*key',
        r'\.asc\b.*pgp',
        r'gpg.*fingerprint',
    ]
    has_pgp = False
    for pat in _pgp_patterns:
        if re.search(pat, body_slice, re.IGNORECASE):
            has_pgp = True
            break
    if has_pgp:
        flags.append({"type": "contact_signal", "value": "pgp_key_found"})

    # Tor contact form detection (TOR2WEB / onion routing references)
    _tor_contact_patterns = [
        r'class[^>]*="contact"',
        r'contact.*form',
        r'tor.*contact',
        r'onion.*contact',
        r'idiot\.onion',
    ]
    has_tor_contact = False
    for pat in _tor_contact_patterns:
        if re.search(pat, lower_body):
            has_tor_contact = True
            break
    if has_tor_contact:
        flags.append({"type": "contact_signal", "value": "tor_contact_form"})

    # Social media links
    social_patterns = {
        "twitter": r'(?:twitter\.com|x\.com)/\w+',
        "mastodon": r'mastodon\.|/\.\w+/@\w+',
        "github": r'github\.com/\w+',
        "telegram": r'telegram\.(?:me|org)/\w+',
    }
    found_social: list[str] = []
    for platform, pat in social_patterns.items():
        if re.search(pat, body_slice, re.IGNORECASE):
            found_social.append(platform)

    if found_social:
        flags.append({
            "type": "contact_signal",
            "value": f"social_links ({', '.join(found_social)})",
        })

    # ── 4. proxy_indicator — CDN / reverse-proxy / WAF headers ────────
    _proxy_header_keys: dict[str, list[str]] = {
        "cloudflare": [
            r'cf-ray', r'cf-cache-status', r'cf-request-id',
            r'x-cloudflare-', r'cdn-cgi',
        ],
        "akamai": [r'akamai', r'x-akamai'],
    }

    # Normalize header keys/values for case-insensitive matching
    all_header_keys_lower = " ".join(resp_headers.keys()).lower()
    all_header_vals_lower = " ".join(str(v) for v in resp_headers.values()).lower()

    checked_proxies: list[str] = []
    for proxy_name, patterns in _proxy_header_keys.items():
        matched = False
        for pat in patterns:
            if pat in all_header_keys_lower or re.search(pat, all_header_vals_lower):
                matched = True
                break
        if matched:
            checked_proxies.append(proxy_name)

    # Generic proxy/CDN detection from Server / X-Cache headers
    server_val_lower = (resp_headers.get("Server") or "").lower()
    xcache_val = resp_headers.get("X-Cache", "") or resp_headers.get("x-cache", "")

    generic_cdn_keywords = [
        ("cloudflare", ["cloudflare", "cf-", "cdn-cgi"]),
        ("akamai", ["akamai", "x-akamai"]),
        ("fastly", ["fastly", "x-served-by"]),
        ("varnish", ["varnish", "x-varnish"]),
        ("squid", ["squid", "via.*squid"]),
        ("nginx/cdn", ["nginx.*cdn", "cdn.*nginx"]),
    ]

    for gw_name, kwlist in generic_cdn_keywords:
        if any(kw in server_val_lower for kw in kwlist):
            if gw_name not in checked_proxies:
                checked_proxies.append(gw_name)
        if any(kw in xcache_val.lower() for kw in ["hit", "miss"]) and gw_name != "nginx/cdn":
            if gw_name not in checked_proxies:
                # Cache header present but no strong identity — could be generic CDN
                pass

    if checked_proxies:
        flags.append({
            "type": "proxy_indicator",
            "value": ", ".join(checked_proxies),
        })

    # ── 5. forum_software (supplementary type) ────────────────────────
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
            if re.search(pat, lower_body):
                flags.append({"type": "forum_software", "value": forum_software})
                break

    # ── 6. redirect_chain (supplementary type) ────────────────────────
    if redirect_depth > 1:
        flags.append({"type": "redirect_chain", "value": f"depth={redirect_depth}"})

    return flags


def _flags_to_summary_lines(flags: list[dict]) -> list[str]:
    """Convert extracted flags into human-readable summary lines.

    Only includes flags that add value to the content summary and avoids
    duplicating info already present in the extractor's output (e.g., tech
    stack is typically handled by _do_classify).  The selected flags
    enhance the user's understanding of a site at a glance:

      - robots_txt       → access restrictions the operator declared
      - contact_signal   → how to reach the operator
      - forum_software   → what platform powers the discussion (complements
                           extractor output which may have missed it)
      - redirect_chain   → indicates unstable / migrating destinations

    Returns a list of summary line strings ready to be appended.
    """
    lines: list[str] = []
    for flag in flags:
        ftype = flag.get("type", "")
        fval = flag.get("value", "")
        if not ftype or not fval:
            continue

        if ftype == "robots_txt":
            lines.append(f"Access policy: {fval}")

        elif ftype == "contact_signal":
            lines.append(f"Contact: {fval}")

        elif ftype == "forum_software":
            # Only include if extractor didn't already report it explicitly
            lines.append(f"Forum software: {fval}")

        elif ftype == "redirect_chain":
            depth = fval.split("=")[-1] if "=" in fval else "?"
            lines.append(f"Redirect chain: depth {depth}")

    return lines


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
    detected_lang: str = ""    # ISO 639-1 code from langid (e.g. "de", "ja")
    found_links: list[str] = field(default_factory=list)
    content_hash: str = ""     # SHA-256 of body for change detection
    last_modified: str = ""    # HTTP Last-Modified header value
    flags: list[dict] = field(default_factory=list)     # extracted signals as {"type": "...", "value": "..."} dicts
    needs_review: bool = False  # True when no extractor claimed or partial extract
    reason: str = ""  # reason string for needs_review (e.g. "no_extractor_claimed")

    # ── protocol-gate fields ───────────────────────────────────────────
    # Populated when the gate fires (i.e. a confident non-HTTP service was
    # detected and the HTTP pipeline was skipped). When the gate did NOT
    # fire (normal HTTP flow), all three fields stay "".
    service_type: str = ""       # human-friendly label ("I2P IRC gateway")
    service_protocol: str = ""   # machine tag ("irc_gateway")
    gate_applied: bool = False   # True when the gate fired for this destination
    gate_confidence: float = 0.0 # classifier confidence at gate-fire time



# ---------------------------------------------------------------------------
# Adaptive backoff — exponential or fixed penalties for dead destinations
# ---------------------------------------------------------------------------

# Backoff intervals in seconds (exponential strategy):
# index N = interval after N consecutive failures.
# 1→60s, 2→300s, 3→1800s, 4→7200s, 5→43200s (12h), capped at 604800s (7 days).
_BACKOFF_INTERVALS = (60, 300, 1800, 7200, 43200, 604800)

# Fixed strategy: constant delay per failure (seconds).
_FIXED_BACKOFF_SECONDS = 300  # 5 minutes per failed attempt

# Phase 3 — Banner cache TTL (7 days).  Banners older than this are considered
# stale and trigger a full re-probe to catch changed protocols/content.
BANNER_CACHE_TTL: int = 604800

# ── Protocol gate ────────────────────────────────────────────────────────────
# Confidence threshold at which the gate fires on a non-HTTP tag.
# Set slightly above 0.80 so that structural heuristics (0.75) do NOT
# trigger the gate — only exact signature matches (1.00) and regex matches
# (0.90) do. The asymmetric cost model: a false "non-HTTP" masks a real site
# (high cost); a false "HTTP" costs one fetch (low cost).
GATE_CONFIDENCE_THRESHOLD: float = 0.85

# Default port used when the gate probes a destination without an explicit
# port hint. I2P web services default to 443.
DEFAULT_GATE_PORT: int = 443



class BackoffStrategy:
    """Named constants for backoff algorithm selection."""
    EXPONENTIAL = "exponential"
    FIXED = "fixed"

    @classmethod
    def valid(cls) -> set[str]:
        return {cls.EXPONENTIAL, cls.FIXED}


def _compute_backoff_interval(
    consecutive_failures: int,
    strategy: str = BackoffStrategy.EXPONENTIAL,
) -> float:
    """Return the backoff delay in seconds for a given failure count.

    ``strategy`` selects the algorithm:
      - "exponential" (default): exponential growth bounded by 7 days.
        consecutive_failures=1 → 60s, 2 → 300s, 3 → 1800s, …
      - "fixed": constant delay per failure
        (_FIXED_BACKOFF_SECONDS = 300s × failure_count).

    For backward compatibility, callers that pass only ``consecutive_failures``
    get exponential behaviour.
    """
    if consecutive_failures <= 0:
        return 0.0

    if strategy == BackoffStrategy.FIXED:
        return float(consecutive_failures) * _FIXED_BACKOFF_SECONDS

    # Default: exponential growth (original behaviour)
    idx = min(consecutive_failures - 1, len(_BACKOFF_INTERVALS) - 1)
    return _BACKOFF_INTERVALS[idx]


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
        self._ensure_services_table()
        self._ensure_simhash_table()
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
                detected_lang   TEXT    DEFAULT '',  -- ISO 639-1 language code (e.g. 'de', 'ja')
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
                CASE WHEN ab.deep_analysis IS NOT NULL AND LENGTH(COALESCE(ab.deep_analysis,'')) > 50
                     THEN TRIM(REPLACE(json_extract(ab.deep_analysis, '$.site_type'), CHAR(10),'· ')) ELSE NULL END AS deep_site_type,
                CASE WHEN ab.deep_analysis IS NOT NULL AND LENGTH(COALESCE(ab.deep_analysis,'')) > 50
                     THEN REPLACE(SUBSTR(json_extract(ab.deep_analysis, '$.purpose'), 1,200), CHAR(10),'· ') ELSE NULL END AS deep_purpose,
                (SELECT datetime(MAX(d2.probed_at),'unixepoch') FROM discoveries d2 
                  WHERE d2.ident_hash_hex = ab.ident_hash_hex AND LENGTH(d2.deep_analysis)>50) AS deep_analyzed_at,
                ab.ident_hash_hex,
                ab.b32_addr,
                ab.status_code,
                ab.body_length,
                ab.title,
                ab.response_time_sec,
                ab.detected_lang,
                ab.via_method,
                ab.last_probed_at,
                ab.content_hash,
                ab.last_modified,
                ab.found_links,
                ab.flags,
                ab.needs_review,
                CASE WHEN ab.deep_analysis IS NOT NULL AND LENGTH(COALESCE(ab.deep_analysis,'')) > 50 THEN CAST(REPLACE(json_extract(ab.deep_analysis, '$.interest_score'), 'null', '') AS INTEGER) ELSE NULL END AS interest_score,
                CASE WHEN ab.deep_analysis IS NOT NULL AND LENGTH(COALESCE(ab.deep_analysis,'')) > 50 THEN json_extract(ab.deep_analysis, '$.interest_reasons') ELSE NULL END AS interest_reasons,
                CAST(ROUND(CASE WHEN COALESCE(ab.found_links, '[]') = '[]' OR ab.body_length IS NULL OR ab.body_length <= 0 THEN 0.0 ELSE ((1 + (LENGTH(ab.found_links) - LENGTH(replace(ab.found_links, ',', ''))) / 2) * LOG(1 + MAX(ab.body_length, 1) / 1000.0)) END, 2) AS REAL) AS content_depth,
                CAST(ROUND(CASE WHEN ab.response_time_sec IS NULL OR ab.response_time_sec <= 0 THEN 0.0 ELSE COALESCE(r.bandwidth_kbps, 0) * COALESCE(ls.num_leases, 0) / (ab.response_time_sec + 1.0) END, 2) AS REAL) AS stability_index,
                ab.deep_analysis,
                r.bandwidth_kbps,
                r.caps    AS router_caps,
                ls.num_leases
            FROM (
                SELECT
                    ident_hash_hex,
                    MAX(COALESCE(NULLIF(b32_addr, ''), NULL)) OVER (
                        PARTITION BY CASE WHEN i2p_dns_name != '' THEN i2p_dns_name ELSE b32_addr END
                    ) AS b32_addr,
                    COALESCE(
                        MAX(COALESCE(NULLIF(i2p_dns_name, ''), NULL)) OVER (
                            PARTITION BY CASE WHEN i2p_dns_name != '' THEN i2p_dns_name ELSE b32_addr END
                        ),
                        MAX(COALESCE(NULLIF(b32_addr, ''), NULL)) OVER (
                            PARTITION BY CASE WHEN i2p_dns_name != '' THEN i2p_dns_name ELSE b32_addr END
                        )
                    ) AS dns_name,
                    reachable,
                    status_code,
                    body_length,
                    title,
                    response_time   AS response_time_sec,
                    via_method,
                    content_type,
                    detected_lang,
                    content_summary,
                    probed_at       AS last_probed_at,
                    content_hash,
                    last_modified,
                    found_links,
                    flags,
                    needs_review,
                    deep_analysis,
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

        if "detected_lang" not in col_info:
            cur.execute(
                "ALTER TABLE discoveries ADD COLUMN detected_lang TEXT DEFAULT ''"
            )
            self._conn.commit()
            logger.info("Added detected_lang column to discoveries table")

        if "deep_analysis" not in col_info:
            cur.execute(
                "ALTER TABLE discoveries ADD COLUMN deep_analysis TEXT DEFAULT ''"
            )
            self._conn.commit()
            logger.info("Added deep_analysis column to discoveries table")

        if "body_html" not in col_info:
            cur.execute(
                "ALTER TABLE discoveries ADD COLUMN body_html TEXT DEFAULT ''"
            )
            self._conn.commit()
            logger.info("Added body_html column to discoveries table")

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
        """Add new columns for SUSI export support, adaptive backoff, and crawl tracking."""
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
        # Adaptive backoff columns — track consecutive failures and compute
        # a backoff_until timestamp so chronically dead destinations don't
        # consume sweep budget every run.
        if "consecutive_failures" not in existing_cols:
            cur.execute(
                "ALTER TABLE targets ADD COLUMN consecutive_failures INTEGER DEFAULT 0"
            )
        if "backoff_until" not in existing_cols:
            cur.execute(
                "ALTER TABLE targets ADD COLUMN backoff_until REAL DEFAULT 0"
            )
        # Crawl depth tracking — 0 for manually seeded, N for auto-discovered
        # at hop distance N from the seed set.
        if "crawl_depth" not in existing_cols:
            cur.execute(
                "ALTER TABLE targets ADD COLUMN crawl_depth INTEGER DEFAULT 0"
            )
        # Provenance chain — comma-separated list of DNS names forming the
        # parentage chain (e.g. "A.i2p,B.i2p" means discovered by A which was
        # linked from B). Empty string for original seeds.
        if "provenance_chain" not in existing_cols:
            cur.execute(
                "ALTER TABLE targets ADD COLUMN provenance_chain TEXT DEFAULT ''"
            )
        # Deep analysis tracking — timestamp of last LLM analysis pass
        if "last_analyzed_at" not in existing_cols:
            cur.execute(
                "ALTER TABLE targets ADD COLUMN last_analyzed_at REAL DEFAULT 0"
            )
        # Raw SUSI DNS destination blob (URL-safe base64 with ~ padding) for hosts.txt export
        if "dest_data" not in existing_cols:
            cur.execute(
                "ALTER TABLE targets ADD COLUMN dest_data TEXT DEFAULT ''"
            )
        # Banner cache — SHA-256 of the protocol banner/fingerprint for this
        # destination.  Used to skip redundant full probes when the banner hasn't
        # changed between sweep cycles, and last_banner_check timestamps each check
        # so stale caches expire after BANNER_CACHE_TTL seconds.
        if "banner_hash" not in existing_cols:
            cur.execute(
                "ALTER TABLE targets ADD COLUMN banner_hash TEXT DEFAULT ''"
            )
        if "last_banner_check" not in existing_cols:
            cur.execute(
                "ALTER TABLE targets ADD COLUMN last_banner_check REAL DEFAULT 0"
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

    def _ensure_services_table(self) -> None:
        """Create the services table if not already present.

        The services table is a first-class store of "what's on the network":
        one row per (host, port) that we have probed and classified, with the
        protocol tag, a human-friendly label, a hash of the banner for cache
        hits, and a short capped copy of the banner text.  The gate writes to
        this table whenever a high-confidence non-HTTP service is detected, so
        the index can later answer questions like "what's on port 6667?"

        Key on (host, port):
          * host: the b32_addr / i2p_dns_name / ident_hash_hex we probed
          * port: the TCP port (443 by default; 6667 for IRC, etc.)

        Idempotent: CREATE TABLE IF NOT EXISTS.
        """
        cur = self._conn.cursor()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS services (
                host          TEXT    NOT NULL,
                port          INTEGER NOT NULL,
                protocol      TEXT    NOT NULL,
                service_type  TEXT    NOT NULL,
                banner_hash   TEXT    NOT NULL,
                banner_text   TEXT    NOT NULL DEFAULT '',
                status        TEXT    NOT NULL DEFAULT 'ok',   -- 'ok' | 'closed' | 'unreachable'
                first_seen    REAL    NOT NULL,
                last_seen     REAL    NOT NULL,
                seen_count    INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (host, port)
            )"""
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_services_protocol ON services (protocol)"
        )
        self._conn.commit()

    # ── services table: record + query ──────────────────────────────────

    def record_service(
        self,
        host: str,
        port: int,
        protocol: str,
        service_type: str,
        banner: bytes,
        status: str = "ok",
    ) -> int:
        """Upsert a row in the services table.
        
        The primary key is (host, port), so repeated probes of the same
        endpoint update the existing row rather than creating duplicates.
        
        Returns the rowid of the affected row.
        """
        import hashlib as _hashlib
        import time as _time
        banner_hash = _hashlib.sha256(banner).hexdigest()
        # Keep banner_text readable: only ASCII-printable bytes, capped at 100.
        # NB: no .strip() — IRC banners legitimately start with a leading
        # space (part of the protocol), and stripping would mangle it.
        _decoded = banner[:100].decode("ascii", errors="ignore")
        banner_text = _decoded.replace("\r", "\\r").replace("\n", "\\n")[:100]
        ts = _time.time()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                INSERT INTO services
                    (host, port, protocol, service_type, banner_hash,
                     banner_text, status, first_seen, last_seen, seen_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT (host, port) DO UPDATE SET
                    protocol     = excluded.protocol,
                    service_type = excluded.service_type,
                    banner_hash  = excluded.banner_hash,
                    banner_text  = excluded.banner_text,
                    status       = excluded.status,
                    last_seen    = excluded.last_seen,
                    seen_count   = services.seen_count + 1
                """,
                (
                    host, port, protocol, service_type, banner_hash,
                    banner_text, status, ts, ts,
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    def get_service(self, host: str, port: int) -> dict | None:
        """Read the services-row for (host, port), or None if absent."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT host, port, protocol, service_type, banner_hash, "
                "banner_text, status, first_seen, last_seen, seen_count "
                "FROM services WHERE host = ? AND port = ?",
                (host, port),
            )
            row = cur.fetchone()
        if row is None:
            return None
        keys = ("host", "port", "protocol", "service_type", "banner_hash",
                "banner_text", "status", "first_seen", "last_seen", "seen_count")
        return dict(zip(keys, row))

    def get_services_by_protocol(self, protocol: str, limit: int = 100) -> list[dict]:
        """Return up to *limit* rows for a given protocol tag (e.g. "irc_gateway").
        Ordered by most-recently-seen first — the freshest service first."""
        keys = ("host", "port", "protocol", "service_type", "banner_hash",
                "banner_text", "status", "first_seen", "last_seen", "seen_count")
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT host, port, protocol, service_type, banner_hash, "
                "banner_text, status, first_seen, last_seen, seen_count "
                "FROM services WHERE protocol = ? "
                "ORDER BY last_seen DESC LIMIT ?",
                (protocol, limit),
            )
            rows = cur.fetchall()
        return [dict(zip(keys, r)) for r in rows]

    def get_services_by_port(self, port: int, limit: int = 100) -> list[dict]:
        """Return up to *limit* rows for a given TCP port (e.g. 6667 for IRC).

        Mirrors get_services_by_protocol() but keyed on port instead of
        protocol tag.  Answers the design-notes question "what's on port 6667?"
        directly — across every host we've classified, freshest first.
        """
        keys = ("host", "port", "protocol", "service_type", "banner_hash",
                "banner_text", "status", "first_seen", "last_seen", "seen_count")
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT host, port, protocol, service_type, banner_hash, "
                "banner_text, status, first_seen, last_seen, seen_count "
                "FROM services WHERE port = ? "
                "ORDER BY last_seen DESC LIMIT ?",
                (port, limit),
            )
            rows = cur.fetchall()
        return [dict(zip(keys, r)) for r in rows]

    def get_all_services(self, limit: int = 100) -> list[dict]:
        """Return up to *limit* service rows across all protocols/ports.

        Ordered by most-recently-seen first.  Used by the services CLI to
        give the operator a full network inventory.
        """
        keys = ("host", "port", "protocol", "service_type", "banner_hash",
                "banner_text", "status", "first_seen", "last_seen", "seen_count")
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT host, port, protocol, service_type, banner_hash, "
                "banner_text, status, first_seen, last_seen, seen_count "
                "FROM services "
                "ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()
        return [dict(zip(keys, r)) for r in rows]

    # ── simhash near-duplicate index ────────────────────────────────────

    def _ensure_simhash_table(self) -> None:
        """Create the simhash_index table if not already present.

        One 64-bit simhash (meta-characteristic) fingerprint per ident so
        near-duplicate *content* detection does not bloat the discoveries
        table.  The hash is over the page body/summary text, independent of
        how the destination was reached (b32 vs dns), so both probe modes of
        one destination share a fingerprint.

        Idempotent: CREATE TABLE IF NOT EXISTS.
        """
        cur = self._conn.cursor()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS simhash_index (
                ident_hash_hex  TEXT    PRIMARY KEY,
                simhash_64bit   INTEGER NOT NULL,
                last_computed   REAL    NOT NULL
            )"""
        )
        # Hamming-distance scans read every row; the table is expected to stay
        # small-to-medium, but an index on the hash lets ORDER BY / range lookups
        # avoid a full table temp-sort as it grows.
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_simhash_hash "
            "ON simhash_index (simhash_64bit)"
        )
        self._conn.commit()

    def _record_simhash_unlocked(self, ident_hash_hex: str, simhash_64bit: int) -> int:
        """Upsert one simhash row. Caller MUST already hold ``self._lock``.

        Split out so ``record_discovery()``, which holds the DB lock for its
        own INSERT, can record a fingerprint without re-acquiring the
        (non-reentrant) ``threading.Lock`` and self-deadlocking.
        """
        cur = self._conn.cursor()
        # SQLite INTEGER is *signed* 8-byte ([-2**63, 2**63)).
        # compute_simhash returns unsigned int in [0, 2**64).
        # Fold to two's-complement signed for storage, restore on read.
        sh = int(simhash_64bit) & 0xFFFFFFFFFFFFFFFF
        if sh >> 63:  # top bit set → represent as signed int64
            sh -= 1 << 64
        cur.execute(
            """
            INSERT INTO simhash_index
                (ident_hash_hex, simhash_64bit, last_computed)
            VALUES (?, ?, ?)
            ON CONFLICT(ident_hash_hex) DO UPDATE SET
                simhash_64bit = excluded.simhash_64bit,
                last_computed = excluded.last_computed
            """,
            (ident_hash_hex, sh, datetime.now(timezone.utc).timestamp()),
        )
        self._conn.commit()
        row_id = cur.lastrowid
        return int(row_id) if row_id is not None else 0

    def record_simhash(self, ident_hash_hex: str, simhash_64bit: int) -> int:
        """Upsert a 64-bit simhash fingerprint for a destination.

        Overwrites any prior fingerprint for ``ident_hash_hex`` (content
        changes across re-probes) and refreshes the ``last_computed`` stamp.

        Returns the rowid of the affected row (0 if the connection state is
        odd — mirrors record_discovery() defensive posture).
        """
        with self._lock:
            return self._record_simhash_unlocked(ident_hash_hex, simhash_64bit)

    def get_simhash(self, ident_hash_hex: str) -> int | None:
        """Read the stored simhash for a destination, or None if absent."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT simhash_64bit FROM simhash_index WHERE ident_hash_hex = ?",
                (ident_hash_hex,),
            )
            row = cur.fetchone()
        return self._to_unsigned_64(row[0]) if row is not None else None

    @staticmethod
    def _to_unsigned_64(v: int) -> int:
        """Restore an unsigned 64-bit int from a signed SQLite INTEGER read.

        SQLite stores signed 8-byte values.  When bit 63 was set at write time
        we stored v − 2⁶⁴.  ``v & 0xFFFFFFFFFFFFFFFF`` recovers the original.
        (Works correctly for values that were already signed-positive too,
        since & with all-ones mask is a no-op.)
        """
        return int(v) & 0xFFFFFFFFFFFFFFFF

    def record_simhash_for_text(self, ident_hash_hex: str, content_text: str) -> int:
        """Compute the simhash for *content_text* and store it for *ident*.

        Convenience wrapper so callers on the probe/analysis path don't have
        to import the pure helper.  Returns 0 for empty / non-string input
        without writing a row (nothing meaningful to fingerprint).
        """
        if not isinstance(content_text, str) or not content_text.strip():
            return 0
        sh = compute_simhash(content_text)
        return self.record_simhash(ident_hash_hex, sh)

    def find_similar(
        self,
        ident_hash_hex: str,
        max_hamming: int = DEFAULT_SIMHASH_MAX_HAMMING,
    ) -> list[dict]:
        """Return stored fingerprints near-duplicate to the target's content.

        ``max_hamming`` is the inclusive Hamming-distance threshold against the
        target's OWN stored fingerprint (0 = exact hash match).  The target
        itself is excluded from the result; other destinations whose simhash is
        within the threshold are returned ordered by distance (closest first),
        each as ``{"ident_hash_hex", "hamming_distance"}``.
        """
        target = self.get_simhash(ident_hash_hex)
        if target is None:
            return []
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT ident_hash_hex, simhash_64bit FROM simhash_index"
            )
            rows = cur.fetchall()
        out: list[dict] = []
        for hh, sh in rows:
            if hh == ident_hash_hex:
                continue
            d = hamming_distance(self._to_unsigned_64(sh), target)
            if d <= max_hamming:
                out.append({"ident_hash_hex": hh, "hamming_distance": d})
        out.sort(key=lambda r: (r["hamming_distance"], r["ident_hash_hex"]))
        return out

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
                            '%s ("%s") [%s]%s %sKB in %.1fs — %s',
                            ab.dns_name,
                            REPLACE(ab.title, '"', "'"),
                            COALESCE(NULLIF(ab.content_type, ''), 'unknown'),
                            CASE WHEN ab.detected_lang IS NOT NULL AND LENGTH(ab.detected_lang) = 2
                                     AND ab.detected_lang != 'en'
                                 THEN printf(' (originally %s)', ab.detected_lang)
                                 ELSE '' END,
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
                /* ── deep analysis site_type (LLM-classified) ── */
                CASE
                    WHEN ab.deep_analysis IS NOT NULL
                         AND LENGTH(COALESCE(ab.deep_analysis, '')) > 50
                    THEN TRIM(REPLACE(
                        json_extract(ab.deep_analysis, '$.site_type'), CHAR(10), '· ')
                    )
                    ELSE NULL
                END AS deep_site_type,
                /* ── deep analysis purpose (LLM-classified) ── */
                CASE
                    WHEN ab.deep_analysis IS NOT NULL
                         AND LENGTH(COALESCE(ab.deep_analysis, '')) > 50
                    THEN REPLACE(
                        SUBSTR(json_extract(ab.deep_analysis, '$.purpose'), 1, 200),
                        CHAR(10), ' · '
                    )
                    ELSE NULL
                END AS deep_purpose,
                (SELECT datetime(MAX(d2.probed_at),'unixepoch') FROM discoveries d2 
                  WHERE d2.ident_hash_hex = ab.ident_hash_hex AND LENGTH(d2.deep_analysis)>50) AS deep_analyzed_at,
                ab.ident_hash_hex,
                ab.b32_addr,
                ab.status_code,
                ab.body_length,
                ab.title,
                ab.response_time_sec,
                ab.detected_lang,
                ab.via_method,
                ab.last_probed_at,
                ab.content_hash,
                ab.last_modified,
                ab.found_links,
                ab.flags,
                ab.needs_review,
                CASE WHEN ab.deep_analysis IS NOT NULL AND LENGTH(COALESCE(ab.deep_analysis,'')) > 50 THEN CAST(REPLACE(json_extract(ab.deep_analysis, '$.interest_score'), 'null', '') AS INTEGER) ELSE NULL END AS interest_score,
                CASE WHEN ab.deep_analysis IS NOT NULL AND LENGTH(COALESCE(ab.deep_analysis,'')) > 50 THEN json_extract(ab.deep_analysis, '$.interest_reasons') ELSE NULL END AS interest_reasons,
                CAST(ROUND(CASE WHEN COALESCE(ab.found_links, '[]') = '[]' OR ab.body_length IS NULL OR ab.body_length <= 0 THEN 0.0 ELSE ((1 + (LENGTH(ab.found_links) - LENGTH(replace(ab.found_links, ',', ''))) / 2) * LOG(1 + MAX(ab.body_length, 1) / 1000.0)) END, 2) AS REAL) AS content_depth,
                CAST(ROUND(CASE WHEN ab.response_time_sec IS NULL OR ab.response_time_sec <= 0 THEN 0.0 ELSE COALESCE(r.bandwidth_kbps, 0) * COALESCE(ls.num_leases, 0) / (ab.response_time_sec + 1.0) END, 2) AS REAL) AS stability_index,
                ab.deep_analysis,
                r.bandwidth_kbps,
                r.caps    AS router_caps,
                ls.num_leases
            FROM (
                SELECT
                    ident_hash_hex,
                    MAX(COALESCE(NULLIF(b32_addr, ''), NULL)) OVER (
                        PARTITION BY CASE WHEN i2p_dns_name != '' THEN i2p_dns_name ELSE b32_addr END
                    ) AS b32_addr,
                    COALESCE(
                        MAX(COALESCE(NULLIF(i2p_dns_name, ''), NULL)) OVER (
                            PARTITION BY CASE WHEN i2p_dns_name != '' THEN i2p_dns_name ELSE b32_addr END
                        ),
                        MAX(COALESCE(NULLIF(b32_addr, ''), NULL)) OVER (
                            PARTITION BY CASE WHEN i2p_dns_name != '' THEN i2p_dns_name ELSE b32_addr END
                        )
                    ) AS dns_name,
                    reachable,
                    status_code,
                    body_length,
                    title,
                    response_time   AS response_time_sec,
                    via_method,
                    content_type,
                    detected_lang,
                    content_summary,
                    probed_at       AS last_probed_at,
                    content_hash,
                    last_modified,
                    found_links,
                    flags,
                    needs_review,
                    deep_analysis,
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
                and "interest_score" in view_sql
                and "currently unreachable" in view_sql
                and "(originally %s)" in view_sql
                and "deep_site_type" in view_sql
                and "deep_analyzed_at" in view_sql
                and "MAX(COALESCE(NULLIF" in view_sql
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
        detected_lang: str = "",
        content_summary: str = "",
        content_hash: str = "",
        last_modified: str = "",
        found_links: list[str] | None = None,
        flags: list[dict] | None = None,
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
                    content_type, detected_lang, content_summary, content_hash, last_modified,
                    found_links, flags, needs_review, error_msg, probed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                       detected_lang=excluded.detected_lang,
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
                 content_type, detected_lang, _truncate(content_summary, 4096),
                 content_hash, last_modified, _json.dumps(found_links or []),
                 _json.dumps(flags or []), int(needs_review), error_msg, now),
            )
            self._conn.commit()

            # ── near-dup fingerprint (v0.4.14 #5a) ──────────────────────
            # Record a simhash for this destination's content so find_similar()
            # can answer "is this a near-duplicate of anything else?" later.
            # Only when we actually have meaningful text to fingerprint.
            # ``content_summary`` may be a MagicMock in tests — guard with
            # isinstance(str) (same posture as the banner-hash guard).
            if (
                isinstance(content_summary, str)
                and content_summary.strip()
                and reachable
            ):
                self._record_simhash_unlocked(
                    ident_hash_hex, compute_simhash(content_summary)
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

    def get_flagged_destinations_with_hints(self, limit: int | None = None) -> list[dict[str, str]]:
        """Return flagged destinations with content_type hints from the last probe.

        Extends get_flagged_destinations() by including content_type and title
        from the most recent discovery record.  The content_type bucket serves as
        a hint for extractor naming and fingerprint detection during skeleton
        generation.

        Args:
            limit: Optional maximum number of destinations to return.

        Returns:
            List of dicts with keys: hash_hex, dns_name, b32_addr, content_type,
            title (all strings, empty string when not available).
        """
        cur = self._conn.cursor()
        if limit is not None and limit < 0:
            raise ValueError(f"limit must be non-negative, got {limit}")
        sql = "SELECT ident_hash_hex, dns_name, b32_addr, content_type, title FROM address_book WHERE needs_review = 1"
        params: list[int | str] = []
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        cur.execute(sql, params)
        results = []
        for row in cur.fetchall():
            results.append({
                "hash_hex": row[0],
                "dns_name": row[1] or "",
                "b32_addr": row[2] or "",
                "content_type": row[3] or "",
                "title": row[4] or "",
            })
        return results

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

    def update_backoff_state(
        self,
        ident_hash_hex: str,
        dns_name: str,
        reachable: bool,
        backoff_strategy: str = BackoffStrategy.EXPONENTIAL,
    ) -> None:
        """Update consecutive_failures and backoff_until after a probe attempt.

        On failure: increment consecutive_failures, compute backoff interval,
        set backoff_until = now + interval, update last_probed_at.

        On success: reset consecutive_failures to 0, clear backoff_until,
        update last_probed_at.

        Args:
            ident_hash_hex: SHA-1 hash (40-char hex) of the destination identity.
            dns_name: .i2p DNS name when present (used as fallback lookup key).
            reachable: Whether this probe attempt succeeded.
            backoff_strategy: "exponential" (default, growing delays) or
                "fixed" (constant delay per failure).
        """
        with self._lock:
            cur = self._conn.cursor()
            now = time.time()

            # Read current state — match by hash if available, otherwise by dns
            if ident_hash_hex:
                cur.execute(
                    "SELECT consecutive_failures FROM targets WHERE ident_hash_hex = ?",
                    (ident_hash_hex,),
                )
            elif dns_name:
                cur.execute(
                    "SELECT consecutive_failures FROM targets WHERE i2p_dns_name = ?",
                    (dns_name,),
                )
            else:
                return  # nothing to update

            row = cur.fetchone()
            if not row:
                logger.warning("Backoff update: target not found in DB, skipping")
                return

            current_failures = int(row[0])

            if reachable:
                # Success — reset counter and clear backoff
                new_failures = 0
                new_backoff = 0.0
                logger.debug(
                    "Backoff reset for %s (was %d failures)",
                    ident_hash_hex or dns_name,
                    current_failures,
                )
            else:
                # Failure — increment and compute backoff interval
                new_failures = current_failures + 1
                interval = _compute_backoff_interval(new_failures, strategy=backoff_strategy)
                new_backoff = now + interval
                logger.info(
                    "Backoff #%d for %s → skip %ds (until %.0f UTC)",
                    new_failures,
                    ident_hash_hex or dns_name,
                    int(interval),
                    new_backoff,
                )

            # Update target
            if ident_hash_hex:
                cur.execute(
                    "UPDATE targets SET "
                    "consecutive_failures = ?, backoff_until = ?, last_probed_at = ? "
                    "WHERE ident_hash_hex = ?",
                    (new_failures, new_backoff, now, ident_hash_hex),
                )
            elif dns_name:
                cur.execute(
                    "UPDATE targets SET "
                    "consecutive_failures = ?, backoff_until = ?, last_probed_at = ? "
                    "WHERE i2p_dns_name = ?",
                    (new_failures, new_backoff, now, dns_name),
                )

            self._conn.commit()


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

        Each dict has keys: i2p_dns_name, ident_hash_hex, b32_raw, dest_data_len, dest_b64.
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
                dest_blob = e.get("dest_b64", "")
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
                        "UPDATE targets SET susi_active = ?, b32_addr = ?, source = ?, "
                        "dest_data = ?, last_updated_at = ? WHERE id = ?",
                        (generation, b32, src, dest_blob, now, row[0]),
                    )
                else:
                    # New entry or hash rotation — insert fresh
                    cur.execute(
                        "INSERT INTO targets (ident_hash_hex, b32_addr, i2p_dns_name, source, susi_active, dest_data) VALUES (?, ?, ?, ?, ?, ?)",
                        (h, b32, dns, src, generation, dest_blob),
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
        skip_backoff: bool = True,
    ) -> list[tuple[str, str]]:
        """Return the target queue as (hash_hex, dns_name) tuples.

        Args:
            filter_mode: Which targets to include.
                - "all"          — every target in the database (default, backward compatible)
                - "reachable_only" — only targets with at least one reachable discovery record
                - "never_probed"   — targets where last_probed_at == 0 (first probe pass)
                - "stale"         — targets probed more than min_age_hours ago
            min_age_hours: Hours threshold for "stale" filter (default 24).
            skip_backoff: When True (default), exclude targets whose backoff_until
                has not yet expired. Set to False to probe everything regardless
                of backoff — useful during initial sweeps or debugging.

        Priorities (within the filtered set):
        1. Previously reachable targets first (highest chance of success).
        2. Entries with valid identity hash (b32 probing capable).
        3. By last_probed_at ascending (older probes first).
        """
        where_clauses: list[str] = []
        params: list = []

        # Adaptive backoff: skip targets still in their backoff window
        if skip_backoff:
            now = time.time()
            where_clauses.append("backoff_until <= ?")
            params.append(now)

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

    def get_new_targets_for_crawl(
        self,
        depth: int = 0,
        source: str = "linked",
        max_count: int | None = None,
    ) -> list[tuple[str, str]]:
        """Return targets eligible for auto-discovery crawl at the given depth.

        These are targets with `source='linked'` (or any specified source),
        matching the requested crawl_depth, that have never been probed
        (last_probed_at == 0). Useful for the next-round of recursive crawling.

        Args:
            depth: Crawl depth to fetch targets at (default 0).
            source: Target source to filter by (default 'linked').
            max_count: Cap the number of targets returned per round.

        Returns:
            List of (ident_hash_hex, dns_name) tuples.
        """
        cur = self._conn.cursor()
        query = (
            "SELECT ident_hash_hex, i2p_dns_name FROM targets "
            "WHERE source = ? AND crawl_depth = ? AND last_probed_at == 0 "
            "ORDER BY first_seen_at ASC"
        )
        params: list = [source, depth]
        if max_count is not None:
            query += f" LIMIT {max_count}"
        cur.execute(query, params)
        return [(r[0], r[1]) for r in cur.fetchall()]

    def get_new_target_count(self) -> int:
        """Return count of targets that have never been probed and are linked-sourced."""
        cur = self._conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM targets WHERE source = 'linked' AND last_probed_at == 0"
        )
        return cur.fetchone()[0]

    def upsert_targets_from_links(
        self,
        linked_sites: list[str],
        source_site: str = "",
        crawl_depth: int = 1,
    ) -> int:
        """Upsert .i2p DNS names discovered while probing another site.

        Each entry gets an empty hash/b32 (DNS-only seed) and records which
        site found it for traceability. Returns the count of newly inserted rows.

        Args:
            linked_sites: List of .i2p DNS names to upsert.
            source_site: The DNS name or label of the parent site that contained
                these links (for provenance chain tracking).
            crawl_depth: How many hops from the original seed this target is.
                Depth 1 = found in a seeded site; depth 2 = found via depth-1, etc.
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
                # Build provenance chain: source_site is the direct parent that found this link.
                # We look up the parent's own provenance chain to build a full lineage.
                chain = dns
                if source_site:
                    parent_chain = ""
                    cur.execute(
                        "SELECT provenance_chain FROM targets WHERE i2p_dns_name = ?",
                        (source_site,),
                    )
                    pr = cur.fetchone()
                    if pr and pr[0]:
                        parent_chain = pr[0]
                    chain = f"{parent_chain} → {dns}" if parent_chain else f"seed → {dns}"
                cur.execute(
                    "INSERT INTO targets (ident_hash_hex, b32_addr, i2p_dns_name, source, source_site, "
                    "crawl_depth, provenance_chain) VALUES (?, ?, ?, 'linked', ?, ?, ?)",
                    ("", "", dns, source_site, crawl_depth, chain),
                )
                added += 1
            self._conn.commit()

        return added

    def update_target_dest_data(
        self,
        ident_hash_hex: str,
        dest_b64: str,
    ) -> bool:
        """Upsert a raw SUSI destination blob into ``targets.dest_data`` for an
        existing target identified by its identity hash.

        This is called after a successful probe when the router's internal DNS
        cache has resolved the destination data.  Only overwrites if the current
        value is empty, so explicit SUSI imports take precedence.

        Args:
            ident_hash_hex: 40-char hex identity hash.
            dest_b64: Raw I2P base64 destination blob (with ``~`` padding preserved).

        Returns:
            True if a row was updated, False if no matching target or already populated.
        """
        with self._lock:
            cur = self._conn.cursor()
            # LENGTH < 20: minimum I2P base64 destination encoding is ~1.7 chars per byte
            # of a 3635-byte destination = 4847+ chars, so any valid blob far exceeds 20.
            cur.execute(
                "UPDATE targets SET dest_data = ?, last_updated_at = ? "
                "WHERE ident_hash_hex = ? AND LENGTH(dest_data) < 20",
                (dest_b64, datetime.now(timezone.utc).timestamp(), ident_hash_hex),
            )
            self._conn.commit()
            return cur.rowcount > 0

    # ── Phase 3 banner cache helpers ───────────────────────────────

    def update_banner_hash(self, ident_hash_hex: str, sha256_hex: str) -> bool:
        """Store or update the cached banner hash for a target.

        Args:
            ident_hash_hex: 40-char hex identity hash.
            sha256_hex: SHA-256 (hex string) of the protocol/banner fingerprint.

        Returns:
            True if an existing row was updated, False if no row matched.
        """
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "UPDATE targets SET banner_hash = ?, last_banner_check = ? "
                "WHERE ident_hash_hex = ?",
                (sha256_hex, now, ident_hash_hex),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def get_banner_cache(self, ident_hash_hex: str) -> tuple[str, float] | None:
        """Retrieve the cached banner hash and timestamp for a target.

        Returns:
            (sha256_hex, last_check_epoch) if a non-empty hash exists, else None.
        """
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT banner_hash, COALESCE(last_banner_check, 0) FROM targets "
                "WHERE ident_hash_hex = ?",
                (ident_hash_hex,),
            )
            row = cur.fetchone()
        if row and row[0]:
            return row[0], float(row[1])
        return None

    def is_banner_stale(self, ident_hash_hex: str) -> bool:
        """Check whether the cached banner hash has expired or is missing.

        Returns True when a full re-probe is warranted (no cache entry, empty
        hash, or last check older than BANNER_CACHE_TTL seconds).
        """
        cached = self.get_banner_cache(ident_hash_hex)
        if cached is None:
            return True
        _, ts = cached
        now = datetime.now(timezone.utc).timestamp()
        return (now - ts) > BANNER_CACHE_TTL

    def update_last_banner_check(self, ident_hash_hex: str) -> bool:
        """Update just the last_banner_check timestamp without changing the hash.

        Used after a quick reachability check confirms the destination is still up
        and the banner hasn't changed — keeps the cache fresh without full reprobing.

        Args:
            ident_hash_hex: 40-char hex identity hash.

        Returns:
            True if an existing row was updated, False if no row matched.
        """
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "UPDATE targets SET last_banner_check = ? "
                "WHERE ident_hash_hex = ? AND banner_hash != ''",
                (now, ident_hash_hex),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def get_target_by_hash(self, ident_hash_hex: str) -> tuple[str, str] | None:
        """Look up a target row by identity hash.

        Returns:
            (ident_hash_hex, b32_addr) tuple or None if not found.
        """
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT ident_hash_hex, COALESCE(b32_addr, i2p_dns_name) FROM targets "
                "WHERE ident_hash_hex = ?",
                (ident_hash_hex,),
            )
            row = cur.fetchone()
        if row:
            return row[0], row[1]
        return None

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
    robots_policy: TypingAny = None,
    service_gate: bool = False,
    port: int = 0,
) -> DiscoveryResult:
    """Probe a single destination by BOTH its b32 key address and .i2p DNS name.

    Returns the best result (most data from fastest successful probe).
    If a DB is provided, records both attempts.
    ``config`` provides proxy host/port settings; defaults to I2PConfig().
    ``timeout`` is the per-target deadline in seconds.
    ``robots_policy`` when set, filters discovered links against Disallow rules.
        Fully blocked sites get a robots_txt flag instead of being crawled deeply.
    ``service_gate`` when True (opt-in), enables the protocol-gate: before any
      HTTP body fetch, a cheap TCP banner is read on the destination's primary
      port and classified.  On a confident non-HTTP match the gate fires —
      a services-table row is written and the HTTP fetch + extractor pipeline
      are skipped, saving a full I2P round-trip.  On HTTP or ambiguous banners
      the normal flow proceeds unchanged.  Default False so existing callers
      and tests are unaffected.
    ``port`` optional hint for the gate's banner port (0 → DEFAULT_GATE_PORT).
    """
    b32_addr = _hex_to_b32_addr(ident_hash_hex) if len(ident_hash_hex) == 40 else ""
    results: list[DiscoveryResult] = []

    # ── Protocol gate (opt-in) ───────────────────────────────────────────
    if service_gate:
        gate_port = port if port else DEFAULT_GATE_PORT
        host = b32_addr or i2p_dns_name or ident_hash_hex
        try:
            tag, banner = probe_tcp_banner(
                host=host, port=gate_port,
                timeout=max(1.5, min(timeout, 4.0)),
                config=config,
            )
            svc = classify_service(banner)
            if svc.is_non_http:
                # Gate fired. Record the service and return early — skip the
                # expensive HTTP body fetch and extractor pipeline.
                if db:
                    # Banner probe outcomes: no bytes = closed/rejected TCP,
                    # bytes present (and classified) = a live non-HTTP service.
                    status = "closed" if not banner else "ok"
                    db.record_service(
                        host=host,
                        port=gate_port,
                        protocol=svc.protocol,
                        service_type=svc.service_type or svc.protocol,
                        banner=banner,
                        status=status,
                    )
                gated_res = DiscoveryResult(
                    b32_addr=b32_addr or host,
                    ident_hash_hex=ident_hash_hex,
                    reachable=True,
                    via_method="banner_gate",
                    probe_mode="banner",
                    status_code=0,
                    error="",
                    service_type=svc.service_type or svc.protocol,
                    service_protocol=svc.protocol,
                    gate_applied=True,
                    gate_confidence=svc.confidence,
                )
                logger.info(
                    "Gate fired on %s:%d → %s (%s, conf=%.2f) — skipping HTTP path",
                    host, gate_port, svc.protocol, svc.service_type, svc.confidence,
                )
                return gated_res
            else:
                logger.debug(
                    "Gate: %s:%d → %s (conf=%.2f) — proceeding to HTTP path",
                    host, gate_port, svc.protocol, svc.confidence,
                )
        except Exception as gate_exc:
            # Gate is best-effort: a network error in the banner probe should
            # not fail the whole destination probe. Fall through to HTTP.
            logger.warning("Gate banner probe failed for %s: %s", host, gate_exc)

    # ── Attempt 1: Hit the b32 key directly (no DNS resolution needed)
    if b32_addr:
        logger.info("Probing http://%s/  (b32 key)", b32_addr)
        res_b32 = _do_probe(
            url=f"http://{b32_addr}/",
            ident_hash_hex=ident_hash_hex,
            i2p_dns_name=i2p_dns_name,
            probe_mode="b32",
            config=config,
            timeout=timeout,
            robots_policy=robots_policy,
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
                detected_lang=res_b32.detected_lang,
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
                config=config,
                timeout=dns_timeout,
                robots_policy=robots_policy,
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
                    detected_lang=res_dns.detected_lang,
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
                config=config,
                timeout=timeout,
                robots_policy=robots_policy,
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
                    detected_lang=res_dns.detected_lang,
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

        # ── Enrich with destination blob from router DNS cache ──────────
        # After a successful probe the Java daemon has already resolved and
        # cached this destination internally.  Fetch it so hosts.txt exports
        # contain proper SUSI base64 blobs instead of falling back to
        # "{b32}.b32.i2p" hostnames (which I2P routers can't import directly).
        if len(ident_hash_hex) == 40:
            dest_blob = _fetch_susi_dest_for_hash(ident_hash_hex, config=config)
            if dest_blob:
                updated = db.update_target_dest_data(ident_hash_hex, dest_blob)
                logger.info(
                    "  [dest] Router cache has destination blob (%dB) for %s%s",
                    len(dest_blob), ident_hash_hex[:12],
                    " — upserted" if updated else " — already populated",
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
                crawl_depth=getattr(db, '_crawl_depth', 1),
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
    robots_policy: TypingAny = None,
) -> DiscoveryResult:
    """Single HTTP fetch through proxy. Returns reachable=0 on any failure.
    
    ``config`` provides proxy host/port settings; defaults to I2PConfig().
    ``timeout`` is the per-target deadline in seconds (default 120).
    The underlying I2PProxyClient uses this as a socket timeout.
    ``robots_policy`` when set, filters discovered links against Disallow rules
        and adds robots_txt flags for blocked or fully-blocked destinations.
    """
    start = time.monotonic()
    try:
        resp = fetch_i2p(url, via="http-proxy", config=config, timeout=timeout)
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
            flags.append({"type": "needs_review", "value": extractor_result.reason})

        # ── Language detection (translation decoupled → translate_summaries.py) ──
        detected_lang = "en"  # default assumption
        tagged_summary_lines: list[str] = list(extractor_result.summary_lines)
        flagged_summary_lines = _flags_to_summary_lines(flags)
        tagged_summary_lines.extend(flagged_summary_lines)
        try:
            from src.translation import detect_language

            det_lang, conf = detect_language(title_text, body_text)

            if det_lang != "en" and conf >= 0.4:
                detected_lang = det_lang
                logger.info(
                    f"  [lang] Detected {det_lang} (conf={conf:.2f}) for {url}"
                )
            elif conf >= 0.4:
                detected_lang = det_lang
        except Exception:
            logger.debug("Language detection skipped")
            pass

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
            detected_lang=detected_lang,
            content_summary="\n".join(tagged_summary_lines),
            found_links=extractor_result.links,
            flags=flags,
            needs_review=extractor_result.needs_review,
            reason=extractor_result.reason,
            content_hash=content_hash,
            last_modified=last_modified,
        )

        # ── robots.txt filtering on discovered links ──────────────
        if robots_policy:
            blocked_links = []
            allowed_links = []
            for link in result.found_links:
                # Each link is a .i2p hostname; we need to check paths too.
                # Since extracted links are just hostnames, we only filter
                # path-level disallow rules against common scraped paths.
                # For simplicity: if the site blocks everything, drop ALL links.
                if robots_policy.is_fully_blocked:
                    blocked_links.append(link)
                else:
                    allowed_links.append(link)

            if blocked_links:
                from src.robots_parser import RobotsPolicy as _Rp
                rp = robots_policy
                assert isinstance(rp, _Rp) or rp is None
                result.found_links = allowed_links
                flags.append({
                    "type": "robots_txt",
                    "value": f"blocked_{len(blocked_links)}_links"
                            + (" (site fully blocked)" if robots_policy.is_fully_blocked else ""),
                })
                logger.info(
                    "  [robots] Blocked %d discovered links for %s (%s)",
                    len(blocked_links),
                    ident_hash_hex[:12],
                    "fully blocked" if robots_policy.is_fully_blocked else "filtered",
                )

        logger.info(
            "  [%s] %s  status=%d  body=%dB  %.1fs%s",
            probe_mode, url, resp.status, len(resp.body), elapsed,
            f"  title={result.title[:40]}" if result.title else "",
        )
        if flags:
            flag_strs = [f"{f.get('type','')}:{f.get('value','')}" for f in flags]
            logger.info("    flags: %s", " | ".join(flag_strs))
        return result

    except Exception as exc:
        elapsed = round(time.monotonic() - start, 2)
        tb = traceback.format_exc()
        logger.warning(
            "  [%s] %s  FAILED %.1fs:\n%s", probe_mode, url, elapsed, tb
        )
        return DiscoveryResult(
            b32_addr=url.split("/")[2] if "/" in url else "",
            ident_hash_hex=ident_hash_hex,
            reachable=False,
            error=f"{exc}\n{tb}",
            response_time_sec=elapsed,
            via_method=probe_mode,
            probe_mode=probe_mode,
        )


# ---------------------------------------------------------------------------
# Phase 3 — Quick reachability probe (banner cache hit path)
# ---------------------------------------------------------------------------

def _quick_reachability_probe(
    url: str,
    ident_hash_hex: str,
    config: I2PConfig | None = None,
    timeout: float = 10.0,
) -> DiscoveryResult:
    """Lightweight connectivity check without full banner extraction.

    Used when the banner cache has a valid entry and we only need to confirm
    the destination is still reachable, not re-extract content.  Sends a HEAD
    request (or GET with minimal body read) and returns a slim DiscoveryResult.

    Args:
        url: Target URL to probe.
        ident_hash_hex: 40-char hex identity hash.
        config: Optional I2PConfig override.
        timeout: Per-target deadline (default 10s, much shorter than full probes).

    Returns:
        DiscoveryResult with reachable/status, no content extraction.
    """
    start = time.monotonic()
    try:
        resp = fetch_i2p(url, via="http-proxy", config=config, timeout=timeout)
        elapsed = round(time.monotonic() - start, 2)
        logger.info(
            "  [cache-hit] %s  status=%d  %.1fs  (banner cached, reachability only)",
            url, resp.status, elapsed,
        )
        return DiscoveryResult(
            b32_addr=url.split("/")[2] if "/" in url else "",
            ident_hash_hex=ident_hash_hex,
            reachable=200 <= resp.status < 500,
            status_code=resp.status,
            body_length=0,
            response_time_sec=elapsed,
            via_method="cache-hit",
            probe_mode="cache-hit",
        )
    except Exception as exc:
        elapsed = round(time.monotonic() - start, 2)
        logger.warning(
            "  [cache-hit] %s  FAILED %.1fs: %s", url, elapsed, exc
        )
        return DiscoveryResult(
            b32_addr=url.split("/")[2] if "/" in url else "",
            ident_hash_hex=ident_hash_hex,
            reachable=False,
            error=str(exc),
            response_time_sec=elapsed,
            via_method="cache-hit",
            probe_mode="cache-hit",
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
    skip_backoff: bool = True,
    backoff_strategy: str = BackoffStrategy.EXPONENTIAL,
    respect_robots: bool = False,
    service_gate: bool = False,
    gate_port: int = 0,
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
        skip_backoff: When True (default), targets with active backoff_until are
            excluded from the probe queue. Set to False to force-probe everything.
        backoff_strategy: "exponential" (default, growing delays) or "fixed"
            (constant 300s delay per failure). Controls how backoff_until is
            computed when updating after each probe attempt.
        respect_robots: When True, fetch robots.txt from each destination before
            probing paths. Disallow rules are enforced — matching paths are skipped
            during link extraction, and fully blocked sites get a flag instead of
            being probed in their entirety.
        service_gate: When True (opt-in, default False), enable the protocol gate —
            before the HTTP body fetch, a TCP banner is read and classified. Confident
            non-HTTP services (IRC/SMTP/BOB/Bittorrent/XMPP) are recorded in the
            services table and skip the HTTP fetch + extractors entirely, saving a
            full I2P round-trip. Ambiguous or HTTP banners proceed normally.
        gate_port: TCP port for the gate's banner probe (0 → DEFAULT_GATE_PORT=443).
            Only used when ``service_gate`` is True.

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
            targets = db.get_targets(filter_mode=filter_mode, min_age_hours=min_age_hours, skip_backoff=skip_backoff)

        # ── Apply limit if requested ────────────────────────────────
        if limit:
            targets = targets[:limit]

        logger.info("Probe queue: %d target(s), delay=%.1fs", len(targets), probe_delay)

        # ── Probe each target (one at a time — I2P is slow) ─────────
        results: list[DiscoveryResult] = []

        # robots.txt cache keyed by DNS name or b32 address — fetch once per destination
        _robots_cache: dict[str, TypingAny] = {}

        # ── Phase 3 counters ────────────────────────────────────────
        cache_hits: int = 0
        cache_misses: int = 0

        for i, (hash_hex, dns_name) in enumerate(targets):
            if i > 0:
                logger.info("Waiting %.1fs before next probe...", probe_delay)
                time.sleep(probe_delay)
            logger.info("--- Probing [%d/%d]: hash=%s  dns=%s", i + 1, len(targets), hash_hex or "(none)", dns_name or "(none)")

            # ── Phase 3: Banner cache check ────────────────────────
            if hash_hex and not db.is_banner_stale(hash_hex):
                logger.info("  [cache] Banner cached & fresh for %s — skipping full probe", dns_name or hash_hex)
                url_to_check = ""
                if dns_name:
                    url_to_check = f"http://{dns_name}/"
                else:
                    target_row = db.get_target_by_hash(hash_hex)
                    if target_row and target_row[1]:
                        url_to_check = f"http://{target_row[1]}.b32.i2p/"

                if url_to_check:
                    res = _quick_reachability_probe(
                        url_to_check, hash_hex, config=config, timeout=min(timeout, 10.0)
                    )
                    db.update_last_banner_check(hash_hex)
                    cache_hits += 1
                    results.append(res)
                    db.update_backoff_state(hash_hex, dns_name, res.reachable, backoff_strategy=backoff_strategy)
                    continue
                else:
                    logger.debug("  [cache] No URL available for reachability check — falling through to full probe")

            cache_misses += 1

            # Fetch robots.txt for this destination (cached to avoid redundant requests)
            robots_policy = None
            if respect_robots and dns_name:
                cache_key = dns_name
                if cache_key not in _robots_cache:
                    from src.robots_parser import fetch_robots_txt
                    robots_policy = fetch_robots_txt(
                        f"http://{dns_name}/",
                        config=cfg,
                        timeout=min(timeout, 30.0),
                    )
                    _robots_cache[cache_key] = robots_policy
                robots_policy = _robots_cache[cache_key]

            res = probe_destination(
                ident_hash_hex=hash_hex,
                i2p_dns_name=dns_name,
                db=db,
                config=config,
                timeout=timeout,
                robots_policy=robots_policy if respect_robots else None,
                service_gate=service_gate,
                port=gate_port,
            )
            results.append(res)

            # ── Phase 3: Update banner cache after full probe ────
            if hash_hex and res.content_hash and isinstance(res.content_hash, str):
                cached = db.get_banner_cache(hash_hex)
                if cached is None or cached[0] != res.content_hash:
                    logger.info(
                        "  [cache] Banner changed for %s (old=%s, new=%s)",
                        dns_name or hash_hex,
                        cached[0] if cached else "(none)",
                        res.content_hash[:12],
                    )
                db.update_banner_hash(hash_hex, res.content_hash)

            # Adaptive backoff: update consecutive_failures and backoff_until
            # based on probe outcome, so chronically dead destinations
            # don't consume sweep budget every run.
            db.update_backoff_state(hash_hex, dns_name, res.reachable, backoff_strategy=backoff_strategy)

        logger.info(
            "Probe complete: %d full probes, %d cache hits (%d skipped)",
            cache_misses, cache_hits, cache_hits,
        )
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
# Auto-crawl: multi-hop discovery with depth control and safety bounds
# ---------------------------------------------------------------------------

def auto_crawl(
    max_depth: int = 2,
    crawl_delay: float = 10.0,
    timeout: float = PROBE_TIMEOUT,
    max_new_targets: int | None = None,
    config: I2PConfig | None = None,
    db_path: str = DEFAULT_DB_PATH,
    db_instance: DiscoveryDB | None = None,
    service_gate: bool = False,
    gate_port: int = 0,
) -> dict:
    """Recursively discover new .i2p destinations by crawling links within depth bounds.

    Workflow per round (depth 1..max_depth):
    1. Query the DB for targets with crawl_depth == current_depth that haven't been probed.
    2. Probe each target — probe_destination() records results and extracts links via
       ``probe_destination()``, which calls ``db.upsert_targets_from_links()`` internally.
    3. After a round completes, count how many NEW targets were seeded. Stop if the safety
       cap is reached or no new links were discovered.

    Safety bounds:
    - ``max_depth``: maximum number of hops from the original seed (default 2).
    - ``max_new_targets``: stop after this many linked targets are in the DB overall.
      Set to None to disable the cap (not recommended for unattended runs).
    - Visited set: each DNS name is only probed once per run — duplicates across parents
      are skipped via ``db.upsert_targets_from_links()`` which uses UNIQUE constraints.

    Rate limits:
    - Unverified targets (source='linked') get longer delays than the default probe_delay,
      since they haven't been confirmed reachable yet. The delay scales with depth:
      depth_1 = crawl_delay * 1.0, depth_2 = crawl_delay * 1.5, etc.

    Args:
        max_depth: Maximum recursion depth (default 2). Depth 1 = sites linked from
            known/seeded destinations; depth 2 = sites linked from depth-1 discoveries.
        crawl_delay: Base delay between probes of linked targets in seconds (default 10s).
            Longer than the default ``probe_delay`` since unverified links are riskier.
        timeout: Per-target probe deadline in seconds (default PROBE_TIMEOUT=120).
        max_new_targets: Maximum total number of newly discovered linked targets to allow
            per run. When reached, crawling stops early. Disable with None.
        config: I2P configuration override.
        db_path: Path to SQLite DB (used when db_instance not provided).
        db_instance: Optional pre-created DiscoveryDB.

    Returns:
        Dict with keys: probes_attempted, new_targets_inserted, depth_reached, rounds_run.
    """
    cfg = config or I2PConfig()
    use_existing_db = db_instance is not None
    db = db_instance or DiscoveryDB(db_path)

    # Set crawl_depth flag on DB so probe_destination() propagates it via upsert
    depth_to_use: int = 1  # incremented each round

    stats = {
        "probes_attempted": 0,
        "new_targets_inserted": 0,
        "depth_reached": 0,
        "rounds_run": 0,
        "domains_per_depth": {},
    }

    try:
        # Initialize crawl tracking on DB instance
        db._crawl_depth = 1

        for depth_round in range(1, max_depth + 1):
            round_start = time.monotonic()

            # Rate limiting scales with depth (exponential backoff for deeper crawls)
            effective_delay = crawl_delay * max(1.0, 1.0 + (depth_round - 1) * 0.5)

            logger.info(
                "=== Crawl round %d/%d — fetching targets at depth=%d, delay=%.1fs ===",
                depth_round, max_depth, depth_round, effective_delay,
            )

            # Fetch targets that were seeded at this depth and haven't been probed yet
            targets = db.get_new_targets_for_crawl(
                depth=depth_round,
                source="linked",
            )

            if not targets:
                logger.info("No unprobed targets at depth %d — crawl finished.", depth_round)
                break

            stats["rounds_run"] += 1
            stats["depth_reached"] = max(stats["depth_reached"], depth_round)

            # Per-depth domain deduplication: only probe unique DNS names in this round.
            seen_dns_this_round: set[str] = set()
            unique_targets: list[tuple[str, str]] = []
            for h, d in targets:
                key = d.lower() if d else h.lower()
                if key and key not in seen_dns_this_round:
                    seen_dns_this_round.add(key)
                    unique_targets.append((h, d))

            logger.info("Depth %d: %d candidate(s), %d unique after domain dedup",
                        depth_round, len(targets), len(unique_targets))

            # Safety cap check before probing this round
            if max_new_targets is not None:
                # Count total new linked targets discovered so far in THIS run.
                # We track this by counting how many unprobed linked targets remain
                # plus probes we've already attempted (which are the ones we consumed).
                # The DB was queried for unprobed at each depth before this check,
                # so current_linked counts unprobed ones not yet touched in this run.
                remaining_unprobed = db.get_new_target_count()
                total_reached_or_remaining = remaining_unprobed + stats["probes_attempted"]
                if total_reached_or_remaining >= max_new_targets:
                    logger.info(
                        "Safety cap reached (%d targets processed/remaining >= %d). Stopping crawl.",
                        total_reached_or_remaining, max_new_targets,
                    )
                    break

            # Update DB crawl_depth so probe_destination->upsert propagates the right level
            db._crawl_depth = depth_round + 1

            # Probe each target in this round
            n_ok = 0
            n_fail = 0
            for i, (hash_hex, dns_name) in enumerate(unique_targets):
                if i > 0:
                    logger.info("Waiting %.1fs before next crawl probe...", effective_delay)
                    time.sleep(effective_delay)

                stats["probes_attempted"] += 1
                label = f"Crawl d={depth_round} [{i+1}/{len(unique_targets)}]"
                target_id = dns_name or hash_hex[:12] + "..."
                logger.info("%s Probing: %s", label, target_id)

                try:
                    result = probe_destination(
                        ident_hash_hex=hash_hex if hash_hex else "",
                        i2p_dns_name=dns_name or "",
                        db=db,
                        timeout=timeout,
                        config=cfg,
                        service_gate=service_gate,
                        port=gate_port,
                    )
                except Exception as exc:
                    logger.warning("  ERROR probing %s: %s", target_id, exc)
                    n_fail += 1
                    continue

                reachable = result.reachable if hasattr(result, "reachable") else False
                if reachable:
                    n_ok += 1
                    ctype = getattr(result, "content_type", "") or ""
                    title = getattr(result, "title", "") or ""
                    logger.info(
                        "  ✓ [%s] status=OK type=%s title=%s links_found=%d",
                        target_id, ctype, title[:40], len(getattr(result, "found_links", []) or []),
                    )
                else:
                    n_fail += 1

            stats["domains_per_depth"][str(depth_round)] = {
                "attempted": len(unique_targets),
                "ok": n_ok,
                "fail": n_fail,
            }

            round_elapsed = round(time.monotonic() - round_start, 1)
            logger.info(
                "Round %d complete: %d attempted, %d ok, %d fail (%.1fs)",
                depth_round, len(unique_targets), n_ok, n_fail, round_elapsed,
            )

        final_sum = db.summary()
        logger.info("Crawl finished — DB summary: %s", final_sum)
        return stats
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
            flag_strs = [f"{f.get('type','')}:{f.get('value','')}" for f in r.flags]
            print(f"    flags:   {' | '.join(flag_strs)}")
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
            # Flags may be dicts {"type": ..., "value": ...} or plain strings (legacy)
            flag_labels = []
            for f in flags_list:
                if isinstance(f, dict):
                    flag_labels.append(f"{f.get('type','')}:{f.get('value','')}")
                else:
                    flag_labels.append(str(f))
            line += f" flags({'|'.join(flag_labels)})"

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

    # ── crawl: recursive link-following with depth and safety caps ────
    crawl_p = sub.add_parser("crawl", help="Recursively discover new destinations from linked sites")
    crawl_p.add_argument(
        "--max-depth",
        type=int,
        default=2,
        help="Maximum crawl depth (hops from seed). Default: 2",
    )
    crawl_p.add_argument(
        "--crawl-delay",
        type=float,
        default=15.0,
        help="Delay between probes in crawl mode (default: 15s, longer than sweep since targets are unverified)",
    )
    crawl_p.add_argument(
        "--max-new-targets",
        type=int,
        default=None,
        help="Safety cap: stop after this many newly discovered linked targets per run. Default: unlimited",
    )
    crawl_p.add_argument(
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
    elif args.command == "crawl":
        stats = auto_crawl(
            max_depth=getattr(args, "max_depth", 2),
            crawl_delay=getattr(args, "crawl_delay", 15.0),
            timeout=getattr(args, "timeout", 120.0),
            max_new_targets=getattr(args, "max_new_targets", None),
            config=cfg,
        )
        print(f"\n{'='*60}")
        print(f"  CRAWL SUMMARY")
        print(f"  Rounds run:           {stats['rounds_run']}")
        print(f"  Max depth reached:    {stats['depth_reached']}")
        print(f"  Probes attempted:     {stats['probes_attempted']}")
        per_depth = stats.get('domains_per_depth', {})
        for d, info in sorted(per_depth.items()):
            print(f"  Depth {d}: attempted={info['attempted']} ok={info['ok']} fail={info['fail']}")
        print(f"{'='*60}\n")
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
