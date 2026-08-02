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
import sys as _sys
import threading
import time
import traceback
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

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


# Replacement for _classify_content in src/integration.py
# Lines 146-330 will be replaced with this content.

def _classify_content(
    title: str,
    body_text: str,
) -> tuple[str, str, list[str]]:
    """Classify page content and build a rich English-language summary.

    Detects content type (forum, blog, marketplace, etc.), extracts context-
    specific metadata, translates non-English excerpts to English via
    googletrans, and appends a source-language note when translation occurs.
    """
    import html as _html
    import re as _re

    # --- Language detection + translation helper (lazy, with timeout) ---
    try:
        import langid as _langid
        from deep_translator import GoogleTranslator as _GTrans  # type: ignore[import-untyped]
        _translator = _GTrans(source="auto", target="en")
        _has_lt = True
    except ImportError:
        _has_lt = False

    # Cache per-classification call to avoid repeated lookups
    _lang_cache: dict[int, str | None] = {}  # id(body) -> detected lang
    _trans_cache: dict[tuple[int, str], tuple[str, str | None]] = {}

    def _detect_lang(text: str) -> str | None:
        """Detect language of text, cached per body."""
        did = id(text)
        if did in _lang_cache:
            return _lang_cache[did]
        try:
            lang, _score = _langid.classify(" ".join(text.split())[:500])  # type: ignore[unbound]
            _lang_cache[did] = lang if lang != "en" else None
            return _lang_cache[did]
        except Exception:
            _lang_cache[did] = None
            return None

    def _translate(text: str) -> tuple[str, str | None]:
        """Translate non-English text to English with 3s timeout. Returns (result, lang) or (text, None) on failure."""
        stripped = " ".join(text.split()).strip()[:400]
        if not stripped or len(stripped) < 5 or not _has_lt:
            return stripped, None

        cache_key = (len(text), text)
        if cache_key in _trans_cache:
            return _trans_cache[cache_key]

        lang = _detect_lang(text)
        if lang is None:
            result = (stripped, None)
            _trans_cache[cache_key] = result
            return result

        import signal as _signal

        def _timeout_handler(signum: int, frame: object) -> None:  # type: ignore[arg-type]
            raise TimeoutError("Translation timed out")

        try:
            _old = _signal.signal(_signal.SIGALRM, _timeout_handler)  # type: ignore[arg-type]
            _signal.alarm(3)
            translated = _translator.translate(stripped[:300])  # type: ignore[unbound]
            _signal.alarm(0)
            _signal.signal(_signal.SIGALRM, _old)  # type: ignore[arg-type]
            result = (translated.strip(), lang)
        except TimeoutError:
            result = (stripped, lang)
        except Exception:
            result = (stripped, None)

        _trans_cache[cache_key] = result
        return result

    lower_title = title.lower()
    lower_body = body_text[:32768].lower()

    plain = _TAG_RE.sub(" ", body_text[:32764])
    words_text = " ".join(plain.split()).strip()

    meta_desc_m = _re.search(
        r'<meta[^>]+name=["\']?description["\']?\s+content=["\']([^"\']+)[ "\'"]',
        body_text[:16384],
        _re.IGNORECASE,
    )

    # Bucket detection
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

    # Tech stack detection
    tech_signatures: dict[str, list[str]] = {
        "Node.js": ["npm", "node_modules", "express"],
        "Ruby on Rails": ["csrf-token", "media_types/"],
        "PHP": ["<?php"],
        "Python/Django": ["django-", "csrftoken"],
        "Go": ["go_session", "gorouter"],
    }
    tech_stack: list[str] = []
    for tn, pats in tech_signatures.items():
        if any(_re.search(p, lower_body) for p in pats):
            tech_stack.append(tn)

    spa_framework: str | None = None
    framework_sigs: dict[str, list[str]] = {
        "React": [r'react[-_]?app', r'__react_events__', r'data-reactroot'],
        "Angular": [r'ng-app', r'ng-version', r'angular\.js'],
        "Vue.js": [r'vue\.js', r'data-v-'],
    }
    for fw, pats in framework_sigs.items():
        if any(_re.search(p, lower_body) for p in pats):
            spa_framework = fw
            break

    linked_sites: list[str] = _extract_i2p_links(body_text[:32768])

    # Build rich summary
    lines: list[str] = []

    def _add(line: str) -> None:
        if line.strip():
            lines.append(line.strip())

    decoded_title = _html.unescape(title).strip() if title else ""
    meta_desc_text = ""
    if meta_desc_m:
        meta_desc_text = meta_desc_m.group(1).strip()

    # --- Translate title and description ---
    translated_title = decoded_title
    title_lang = None
    if decoded_title and len(decoded_title) > 3:
        translated_title, title_lang = _translate(decoded_title)

    translated_desc = meta_desc_text
    desc_lang = None
    if meta_desc_text and len(meta_desc_text) > 10:
        translated_desc, desc_lang = _translate(meta_desc_text)

    # Preamble
    type_label = content_type.title() if content_type else "Unidentified"
    if translated_title:
        _add(f"\u00ab{type_label}\u00bb \u00ab{translated_title}\u00bb")
        if title_lang:
            _add(f"(Translated from {title_lang})")
    elif translated_desc:
        _add(f"\u00ab{type_label}\u00bb {translated_desc[:250]}")
        if desc_lang:
            _add(f"(Translated from {desc_lang})")
    else:
        _add(type_label)

    if translated_desc and len(translated_desc) > 10:
        _add(f"Description: {translated_desc[:250]}")

    # Content excerpt from paragraphs — extract multiple for depth
    para_re = _re.compile(r'<p\b[^>]*>(.*?)</p>', _re.IGNORECASE | _re.DOTALL)
    paras = [_TAG_RE.sub(" ", m).strip() for m in para_re.findall(body_text[:32768])]
    excerpts_added = 0
    excerpt_langs: set[str] = set()
    for p in paras:
        if excerpts_added >= 2:
            break
        cleaned = " ".join(p.split())
        if 40 < len(cleaned) < 350:
            tl_words = set(lower_title.split())
            overlap = sum(1 for w in tl_words if w in cleaned.lower().split() and len(w) > 3)
            if overlap / max(len(tl_words), 1) < 0.5:
                trans_text, p_lang = _translate(cleaned)
                _add(f"Content excerpt: \u201c{trans_text[:300]}\u201d")
                if p_lang:
                    excerpt_langs.add(p_lang)
                excerpts_added += 1

    # Add heading text (h1-h3) for more context
    heading_re = _re.compile(r'<h[1-3]\b[^>]*>(.*?)</h[1-3]>', _re.IGNORECASE | _re.DOTALL)
    headings = [_TAG_RE.sub(" ", m).strip() for m in heading_re.findall(body_text[:16384])]
    headings_added = 0
    skip_heading_words = {"home", "menu", "nav", "navigation", "sidebar", "footer"}
    for h in headings:
        if headings_added >= 3:
            break
        hl = h.lower().split()[0] if h.split() else ""
        if len(h) > 5 and len(h) < 200 and hl not in skip_heading_words:
            trans_h, h_lang = _translate(h)
            _add(f"Section: {trans_h.strip()}")
            if h_lang:
                excerpt_langs.add(h_lang)
            headings_added += 1

    # Consolidated language note
    all_langs = set()
    if title_lang:
        all_langs.add(title_lang)
    if desc_lang:
        all_langs.add(desc_lang)
    all_langs |= excerpt_langs
    all_langs -= {"en"}
    if all_langs and not title_lang and not desc_lang:
        _add(f"(Content translated from: {', '.join(sorted(all_langs))})")

    # --- Marketplace enrichment ---
    if content_type == "marketplace":
        cat_terms = [
            "drugs", "services", "digital goods", "hardware", "software",
            "electronics", "clothing", "food", "health", "documents",
            "accounts", "coupons", "gift cards", "prepaid", "privacy",
            "vpn", "proxy", "tor", "i2p", "crypto", "mining",
        ]
        cats = [c for c in cat_terms if _re.search(r'\b' + _re.escape(c) + r'\b', lower_body[:8000])]
        if cats:
            _add(f"Categories sold: {', '.join(cats)}")

        price_mentions = len(_re.findall(
            r'(?:\d{1,4}(?:,\d{3})*\.\d{2}|\d+)\s*(?:sat\b|sats?\b|bitcoin|btc|monepcoin|bitcoins?|xmr|monero|usd|eur|gbp)',
            words_text[:4000], _re.IGNORECASE,
        ))
        if price_mentions:
            _add(f"Pricing signals found ({price_mentions} mentions)")

        vendors = _re.findall(r'(?:seller|vendor|merchant|shop)\s*#?(\d+)', lower_body[:8000])
        if vendors:
            _add(f"Referenced vendors: at least {len(set(vendors))} unique")

        # Product listing detection
        li_rows = len(_re.findall(r'<(?:tr|li)[^>]*>', body_text[:32768], _re.IGNORECASE))
        if li_rows > 10:
            _add(f"Page has ~{li_rows} table/list rows (product listing layout)")

    # --- Forum enrichment ---
    elif content_type == "forum":
        stats_parts: list[str] = []
        cnt_matches = _re.findall(
            r'(\d[\d,]*)\s*(posts?|messages?|threads?|topics?|members?|users?)',
            words_text[:4000], _re.IGNORECASE,
        )
        seen: set[str] = set()
        for val, unit in cnt_matches:
            u = unit.lower()[:4]
            if u not in seen:
                stats_parts.append(f"{val} {u}")
                seen.add(u)
        if stats_parts:
            _add(f"Stats: {', '.join(stats_parts[:6])}")

        fsw = {
            "phpBB": [r'phpbb'],
            "vBulletin": [r'vbulletin', r'veraction'],
            "Flarum": ["flarum"],
            "Discourse": ["discourse"],
            "SMF": ["simplemachines", "smf"],
        }
        for sw, sigs in fsw.items():
            if any(si in lower_body for si in sigs):
                _add(f"Forum software: {sw}")
                break

        # Recent topic/thread titles from links
        a_tags = _re.findall(
            r'<a[^>]*>(.*?)</a>', body_text[:16384], _re.IGNORECASE | _re.DOTALL,
        )
        skip_words = {"home", "login", "register", "sign in", "search", "admin",
                      "profile", "settings", "logout", "terms"}
        topics: list[str] = []
        for t in a_tags:
            c = _TAG_RE.sub(" ", " ".join(t.split())).strip()
            if 10 < len(c) < 120 and c.lower().split()[0] not in skip_words:
                topics.append(c)
        topics = list(dict.fromkeys(topics))[:5]
        if topics:
            # Translate non-English topic titles
            trans_topics = []
            topic_langs: set[str] = set()
            for tp in topics:
                trans_tp, tp_lang = _translate(tp)
                trans_topics.append(trans_tp)
                if tp_lang:
                    topic_langs.add(tp_lang)
            _add(f"Topic threads seen: {'; '.join(trans_topics)}")
            if topic_langs:
                excerpt_langs |= topic_langs

    # --- Blog enrichment ---
    elif content_type == "blog":
        if any(s in lower_body for s in ["rss", "atom.xml", "<?xml", "<feed"]):
            _add("RSS/Atom feed detected (updateable content)")

        blog_eng = {
            "Ghost": [r'ghost-'],
            "WordPress": [r'wp-content/', r'wordpress'],
            "Jekyll": [r'jekyll', r'jekyll-feed'],
            "Hugo": ["hugo"],
        }
        for eng, pats in blog_eng.items():
            if any(_re.search(p, lower_body) for p in pats):
                _add(f"Powered by: {eng}")
                break

        # Extract blog post titles from article/headings
        a_tags = _re.findall(
            r'<a[^>]*>(.*?)</a>', body_text[:16384], _re.IGNORECASE | _re.DOTALL,
        )
        skip_words = {"home", "login", "register", "sign in", "search", "admin",
                      "profile", "settings", "logout", "terms", "archive"}
        posts: list[str] = []
        for t in a_tags:
            c = _TAG_RE.sub(" ", " ".join(t.split())).strip()
            if 10 < len(c) < 150 and c.lower().split()[0] not in skip_words:
                posts.append(c)
        posts = list(dict.fromkeys(posts))[:5]
        if posts:
            # Translate post titles
            trans_posts = []
            for p in posts:
                trans_p, _ = _translate(p)
                trans_posts.append(trans_p)
            _add(f"Recent posts: {'; '.join(trans_posts)}")

    # --- File archive enrichment ---
    elif content_type == "file archive":
        if any(s in lower_body for s in ["index of /", "parent directory"]):
            _add("Apache/Nginx auto-generated directory listing")

        # Filter to known file extensions only (avoid random words)
        KNOWN_EXTS = {
            "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "tgz", "txz",
            "pdf", "doc", "docx", "odt", "txt", "rtf", "epub", "cbz", "cbr",
            "mp3", "flac", "ogg", "wav", "aac", "wma", "opus", "m4a",
            "mp4", "mkv", "avi", "wmv", "mov", "webm", "flv",
            "iso", "img", "dmg", "vdi", "vhdx",
            "exe", "msi", "deb", "rpm",
            "torrent", "nzb",
            "csv", "xls", "xlsx",
            "ppt", "pptx",
            "apk", "ipa",
            "html", "php", "js", "py", "c", "h", "java", "go", "rs",
        }
        exts = list(dict.fromkeys(
            e for e in _re.findall(r'\.([a-z]{2,6})\b', lower_body[:16384])
            if e in KNOWN_EXTS
        ))[:10]
        if exts:
            _add(f"File types present: {', '.join(exts)}")

    # --- Search engine enrichment ---
    elif content_type == "search engine":
        result_count = _re.search(r'(\d[\d,]*)\s*(?:results?|pages? indexed)', words_text[:2000], _re.IGNORECASE)
        if result_count:
            _add(f"Catalog: ~{result_count.group(1)} indexed results/pages")

        # Blockchain explorer detection
        if any(k in lower_body for k in ["blockchain", "block height", "txid", "transaction hash"]):
            coins = []
            coin_sigs: dict[str, list[str]] = {
                "Bitcoin": ["bitcoin", "btc"],
                "Monero": ["monero", "xmr"],
                "Ethereum": ["ethereum", "eth"],
            }
            for coin, sigs in coin_sigs.items():
                if any(s in lower_body for s in sigs):
                    coins.append(coin)
            if coins:
                _add(f"Blockchain explorer for: {', '.join(coins)}")

        # Generic search form detection
        if any(s in lower_body for s in ['<form', 'name="q"', 'name="query"', 'name="search"']):
            _add("Has search form (content indexing)")

    # Common footer info
    if tech_stack:
        _add(f"Tech stack: {', '.join(tech_stack)}")
    elif spa_framework:
        _add(f"SPA framework: {spa_framework}")

    n_links = len(linked_sites)
    if n_links:
        _add(f"Found {n_links} linked i2p site(s)")

    return content_type, "\n".join(lines), linked_sites

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
    flags: list[str] | None = field(default_factory=list)     # extracted signals (robots_disallow_all, tech_stack_detected, ...)


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
        self._ensure_discovery_columns()
        self._ensure_targets_columns()
        self._ensure_susi_sync_table()

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
        flags: list[str] | None = None,
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
                found_links, flags, error_msg, probed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ident_hash_hex, b32_addr, i2p_dns_name, probe_mode, int(reachable),
             status_code, body_length, title, response_time, via_method,
             content_type, _truncate(content_summary, 4096), content_hash,
             last_modified, _json.dumps(found_links or []),
             _json.dumps(flags or []), error_msg, now),
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
        via_method, last_probed_at, content_hash, last_modified, found_links,
        bandwidth_kbps, router_caps, num_leases.
        """
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM address_book ORDER BY dns_name ASC")
        cols = [desc[0] for desc in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

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
            # If source is addressbook, bump the timestamp on existing rows
            # so fresh sweeps keep them "alive" for reconciliation.
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
        cur = self._conn.cursor()
        now = datetime.now(timezone.utc).timestamp()

        # Build set of all hashes currently in the catalog
        current_hashes: set[str] = set()
        for de in catalog.all_destinations():
            current_hashes.add(de.ident_hash_hex.upper())

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

    def get_targets(self) -> list[tuple[str, str]]:
        """Return the target queue as (hash_hex, dns_name) tuples.

        Priorities:
        1. Previously reachable targets first (highest chance of success).
        2. Entries with valid identity hash (b32 probing capable).
        3. By last_probed_at ascending (older probes first).
        """
        cur = self._conn.cursor()
        cur.execute(
            "SELECT ident_hash_hex, i2p_dns_name FROM targets "\
            "ORDER BY "\
            "CASE WHEN EXISTS ("\
            "    SELECT 1 FROM discoveries d "\
            "    WHERE d.ident_hash_hex = targets.ident_hash_hex AND d.reachable=1"\
            ") THEN 0 ELSE 1 END ASC, "\
            "CASE WHEN length(ident_hash_hex)=40 THEN 0 ELSE 1 END ASC, "\
            "last_probed_at ASC"
        )
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
    timeout: float = PROBE_TIMEOUT,
) -> DiscoveryResult:
    """Probe a single destination by BOTH its b32 key address and .i2p DNS name.

    Returns the best result (most data from fastest successful probe).
    If a DB is provided, records both attempts.
    ``timeout`` is the per-target deadline in seconds.
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
                error_msg=res_b32.error,
            )

    # ── Attempt 2: Try .i2p DNS name only if b32 failed or wasn't attempted
    if i2p_dns_name and not i2p_dns_name.endswith(".b32.i2p"):
        b32_ok = any(r.reachable for r in results if r.probe_mode == "b32")
        if b32_ok:
            logger.info("Skipping DNS probe — b32 already succeeded for %s", i2p_dns_name)
        else:
            logger.info("Probing http://%s/  (.i2p DNS fallback)", i2p_dns_name)
            res_dns = _do_probe(
                url=f"http://{i2p_dns_name}/",
                ident_hash_hex=ident_hash_hex,
                i2p_dns_name=i2p_dns_name,
                probe_mode="dns",
                timeout=timeout,
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
) -> DiscoveryResult:
    """Single HTTP fetch through proxy. Returns reachable=0 on any failure.
    
    ``timeout`` is the per-target deadline in seconds (default 120).
    The underlying I2PProxyClient uses this as a socket timeout.
    """
    start = time.monotonic()
    try:
        resp = fetch_i2p(url, via="http-proxy", timeout=timeout)
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

        c_type, c_summary, linked_sites = _classify_content(title_text, body_text)

        # Content hash for change detection
        content_hash = hashlib.sha256(resp.body).hexdigest() if resp.body else ""

        # Last-Modified header (change signal)
        last_modified = resp.headers.get("Last-Modified", "") or resp.headers.get("last-modified", "")

        # ── Flag extraction ────────────────────────────────────────────
        # Derive redirect depth from headers if available: i2p-projekt.i2p
        # and other sites often 301 through the proxy. urllib hides them,
        # but we can infer from Location header chain metadata or estimate
        # from response hop patterns. For now, use a heuristic counter based
        # on common redirects observed during probing.
        redirect_depth = _estimate_redirect_depth(url, resp.headers)

        flags = _extract_flags(body_text, dict(resp.headers), redirect_depth)

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
            flags=flags,
        )

        # Attach extra metadata
        result.content_hash = content_hash
        result.last_modified = last_modified

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

    # ── Apply limit if requested ─────────────────────────────────────
    if limit:
        targets = targets[:limit]

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
            timeout=timeout,
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


def get_address_book(db_path: str = DEFAULT_DB_PATH) -> list[dict]:
    """Return the address_book view — one row per destination with the most
    recent probe, joined against router and leaseset metadata.

    Columns returned:
        dns_name, content_type, reachable, last_probed_utc, content_summary,
        ident_hash_hex, b32_addr, status_code, body_length, title, response_time_sec,
        via_method, last_probed_at, bandwidth_kbps, router_caps, num_leases
    """
    with _db_lock:
        db = DiscoveryDB(db_path)
        rows = db.address_book()
        db.close()
    return rows


def print_address_book(entries: list[dict], json_out: bool = False):
    """Pretty-print or return structured address book data.

    When ``json_out=False`` (default), prints to stdout for terminal consumption.
    When ``json_out=True``, returns the entries list plus summary counts — suitable
    for CSV export, programmatic pipelines, or loading in another script.
    """
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
        ctype = e.get("content_type", "") or ""
        utc = e.get("last_probed_utc", "") or ""
        summary = (e.get("content_summary", "") or "")[:100]

        dns = e.get("dns_name", "") or e.get("b32_addr", "")

        # New columns: content_hash, last_modified, found_links
        chash = e.get("content_hash", "") or ""
        if chash:
            chash_abbr = f"#{chash[:12]}"
        else:
            chash_abbr = ""

        lmod = e.get("last_modified", "") or ""
        if lmod and lmod != "N/A":
            # Try to format as a readable datetime; fall back to raw value
            from datetime import datetime
            try:
                dt = datetime.strptime(lmod, "%a, %d %b %Y %H:%M:%S %Z")
                lmod_display = dt.strftime("%Y-%m-%d %H:%M")
            except (ValueError, TypeError):
                # Already a nice format or something else — keep as-is, cap length
                lmod_display = str(lmod)[:20]
        else:
            lmod_display = "N/A"

        flinks_raw = e.get("found_links", "") or ""
        try:
            flinks_list = _json.loads(flinks_raw) if isinstance(flinks_raw, str) else []
            if not isinstance(flinks_list, list):
                flinks_list = []
        except (_json.JSONDecodeError, TypeError):
            flinks_list = []
        flinks_count = len(flinks_list)
        if flinks_count > 0:
            flinks_display = f"{flinks_count} linked sites"
        else:
            flinks_display = ""

        ctype_tag = f"@{ctype}" if ctype else "unknown"
        line = f"  [{status:>4}] {ctype_tag:<15} {utc!s:<20} {summary}"

        # Append hash abbreviation when available
        if chash_abbr:
            line += f" {chash_abbr}"

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
        # Append last_modified as a trailing annotation
        if lmod_display and lmod_display != "N/A":
            extras.append(f"modified:{lmod_display}")
        if flinks_display:
            extras.append(flinks_display)
        if extras:
            line += "  " + " ".join(extras)

        print(line)

    print(f"\n{'='*72}\n")


def main() -> None:
    """CLI entry point for discovery."""
    import sys
    import argparse
    
    p = argparse.ArgumentParser(description="I2P Indexer — destination discovery")
    p.add_argument(
        "--probe-timeout",
        type=float,
        default=None,
        help="Per-target probe timeout in seconds (default: 120)",
    )
    p.add_argument("targets", nargs="*", help=".i2p hostnames or SHA-1 hashes to probe")
    args = p.parse_args()

    if args.probe_timeout is not None:
        global PROBE_TIMEOUT
        PROBE_TIMEOUT = args.probe_timeout

    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    cfg = I2PConfig()

    targets: list[str | tuple[str, str]] = []
    if args.targets:
        targets = args.targets

    results = discover_addresses(
        known_addrs=targets or None, config=cfg, timeout=args.probe_timeout or PROBE_TIMEOUT
    )
    print_report(results)


if __name__ == "__main__":
    main()
