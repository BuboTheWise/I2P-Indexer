"""HtmlExtractor — standard HTML/web content classifier.

Migrated from _classify_content in src/integration.py (lines 147-572).
Handles HTML pages with keyword-based type detection, meta description
extraction, paragraph/heading extraction, per-type enrichment (forum
stats, blog posts, marketplace categories), and a translation layer.

This is the default built-in extractor — versioned in git alongside
the rest of the codebase.  Additional user-created plugins live in
ext_plugins/ and are auto-discovered on import.
"""
from __future__ import annotations

import html as _html
import re
import logging

from src.extractors import BaseExtractor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex helpers (duplicated here so the plugin is self-contained)
# ---------------------------------------------------------------------------

_TAG_RE = re.compile(r"<[^>]+>")

_I2P_LINK_RE = re.compile(
    r"([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)*\.i2p)",
    re.IGNORECASE,
)

_HTML_START_RE = re.compile(
    r"^[\s]*(?:<!DOCTYPE|<html|<head|<body|<meta|<title)", re.IGNORECASE
)


def _extract_i2p_links(body_text: str) -> list[str]:
    """Return unique .i2p hosts from body text, including multi-level domains."""
    return list({h.strip().lower() for h in _I2P_LINK_RE.findall(body_text[:32768])})





# ---------------------------------------------------------------------------
# HtmlExtractor
# ---------------------------------------------------------------------------

class HtmlExtractor(BaseExtractor):
    """Classifier for standard HTML/web content.

    This is the baseline extractor — it should match most HTTP responses
    that return HTML pages.  It implements the full _classify_content logic
    from integration.py with one addition: when the body has meaningful
    data but extraction yields only ≤1 line, it returns ``needs_review``
    so the orchestrator flags the destination for analyzer inspection.
    """

    priority = 90  # Run before more specialized extractors

    def can_handle(self, body_text: str, headers: dict, status_code: int) -> bool:  # type: ignore[override]
        """Return True when response looks like HTML web content."""
        # Check Content-Type header
        ct = headers.get("Content-Type", "").lower()
        if "text/html" in ct:
            return True

        # Reject known XML types that aren't HTML
        if any(sub in ct for sub in ("application/xml", "application/rss", "application/atom",
                                     "application/json", "application/xhtml")):
            return False

        # Body starts with HTML markers
        if _HTML_START_RE.match(body_text.lstrip()):
            return True

        # Fallback: body has recognizable HTML structure (tags + some text)
        tag_count = len(_TAG_RE.findall(body_text[:8192]))
        if tag_count >= 3 and len(body_text.strip()) > 50:
            return True

        return False

    def extract(self, title: str, body_text: str, headers: dict):  # type: ignore[override]
        """Extract content classification from HTML response.

        Returns (content_type_bucket, summary_lines, linked_i2p_sites).
        """
        return _do_classify(title, body_text)


# ---------------------------------------------------------------------------
# Core classification logic (port of _classify_content)
# ---------------------------------------------------------------------------

def _do_classify(
    title: str,
    body_text: str,
) -> tuple[str, list[str], list[str]]:
    """Classify page content and build a rich summary.

    Detects content type (forum, blog, marketplace, etc.), extracts context-
    specific metadata, and produces English-language summaries from the
    page text without any translation step.

    Returns (content_type, summary_lines_list, linked_i2p_sites).
    """

    lower_title = title.lower()
    lower_body = body_text[:32768].lower()

    plain = _TAG_RE.sub(" ", body_text[:32764])
    words_text = " ".join(plain.split()).strip()

    # --- Meta description extraction ---
    meta_desc_m = re.search(
        r'<meta[^>]+name=["\']?description["\']?\s+content=["\']([^"\']+)[\"\']',
        body_text[:16384],
        re.IGNORECASE,
    )

    # Fallback: reversed attribute order (content before name)
    if not meta_desc_m:
        meta_desc_m = re.search(
            r'<meta[^>]+content=["\']([^"\']+)[\"\']\s+name=["\']?description["\']?',
            body_text[:16384],
            re.IGNORECASE,
        )

    # Fallback: og:description (Open Graph) — very common on modern sites
    if not meta_desc_m:
        meta_desc_m = re.search(
            r'<meta[^>]+property=["\']?og:description["\']?\s+content=["\']([^"\']+)[\"\']',
            body_text[:16384],
            re.IGNORECASE,
        )

    # --- Bucket detection ---
    type_keywords: list[tuple[str, list[str]]] = [
        ("blog", ["blog", "diary", "journal", "entries"]),
        ("forum", ["forum", "board", "thread", "topic"]),
        ("wiki", ["wiki", "knowledge base", "mediawiki"]),
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

    # --- Tech stack detection ---
    tech_signatures: dict[str, list[str]] = {
        "Node.js": ["npm", "node_modules", "express"],
        "Ruby on Rails": ["csrf-token", "media_types/"],
        "PHP": ["<?php"],
        "Python/Django": ["django-", "csrftoken"],
        "Go": ["go_session", "gorouter"],
    }
    tech_stack: list[str] = []
    for tn, pats in tech_signatures.items():
        if any(re.search(p, lower_body) for p in pats):
            tech_stack.append(tn)

    spa_framework: str | None = None
    framework_sigs: dict[str, list[str]] = {
        "React": [r'react[-_]?app', r'__react_events__', r'data-reactroot'],
        "Angular": [r'ng-app', r'ng-version', r'angular\.js'],
        "Vue.js": [r'vue\.js', r'data-v-'],
    }
    for fw, pats in framework_sigs.items():
        if any(re.search(p, lower_body) for p in pats):
            spa_framework = fw
            break

    linked_sites: list[str] = _extract_i2p_links(body_text[:32768])

    # --- Build rich summary (as lines list) ---
    lines: list[str] = []

    def _add(line: str) -> None:
        if line.strip():
            lines.append(line.strip())

    decoded_title = _html.unescape(title).strip() if title else ""
    meta_desc_text = ""
    if meta_desc_m:
        meta_desc_text = meta_desc_m.group(1).strip()

    # Preamble — bucket label + title/description, no translation
    type_label = content_type.title() if content_type else "Unidentified"
    if decoded_title:
        _add(f"{type_label}: {decoded_title[:200]}")
    elif meta_desc_text:
        _add(f"{type_label}: {meta_desc_text[:250]}")
    else:
        _add(type_label)

    if meta_desc_text and len(meta_desc_text) > 10:
        _add(f"Description: {meta_desc_text[:250]}")

    # Content excerpt from paragraphs — extract multiple for depth
    para_re = re.compile(r'<p\b[^>]*>(.*?)</p>', re.IGNORECASE | re.DOTALL)
    paras = [_TAG_RE.sub(" ", m).strip() for m in para_re.findall(body_text[:32768])]
    excerpts_added = 0
    for p in paras:
        if excerpts_added >= 2:
            break
        cleaned = " ".join(p.split())
        if 40 < len(cleaned) < 350:
            tl_words = set(lower_title.split())
            overlap = sum(1 for w in tl_words if w in cleaned.lower().split() and len(w) > 3)
            if overlap / max(len(tl_words), 1) < 0.5:
                _add(f"Content excerpt: \"{cleaned[:300]}\"")
                excerpts_added += 1

    # Add heading text (h1-h3) for more context
    heading_re = re.compile(r'<h[1-3]\b[^>]*>(.*?)</h[1-3]>', re.IGNORECASE | re.DOTALL)
    headings = [_TAG_RE.sub(" ", m).strip() for m in heading_re.findall(body_text[:16384])]
    headings_added = 0
    skip_heading_words = {"home", "menu", "nav", "navigation", "sidebar", "footer"}
    for h in headings:
        if headings_added >= 3:
            break
        hl = h.lower().split()[0] if h.split() else ""
        if len(h) > 5 and len(h) < 200 and hl not in skip_heading_words:
            _add(f"Section: {h.strip()}")
            headings_added += 1

    # --- Marketplace enrichment ---
    if content_type == "marketplace":
        cat_terms = [
            "drugs", "services", "digital goods", "hardware", "software",
            "electronics", "clothing", "food", "health", "documents",
            "accounts", "coupons", "gift cards", "prepaid", "privacy",
            "vpn", "proxy", "tor", "i2p", "crypto", "mining",
        ]
        cats = [c for c in cat_terms if re.search(r'\b' + re.escape(c) + r'\b', lower_body[:8000])]
        if cats:
            _add(f"Categories sold: {', '.join(cats)}")

        price_mentions = len(re.findall(
            r'(?:\d{1,4}(?:,\d{3})*\.\d{2}|\d+)\s*(?:sat\b|sats?\b|bitcoin|btc|monepcoin|bitcoins?|xmr|monero|usd|eur|gbp)',
            words_text[:4000], re.IGNORECASE,
        ))
        if price_mentions:
            _add(f"Pricing signals found ({price_mentions} mentions)")

        vendors = re.findall(r'(?:seller|vendor|merchant|shop)\s*#?(\d+)', lower_body[:8000])
        if vendors:
            _add(f"Referenced vendors: at least {len(set(vendors))} unique")

        # Product listing detection
        li_rows = len(re.findall(r'<(?:tr|li)[^>]*>', body_text[:32768], re.IGNORECASE))
        if li_rows > 10:
            _add(f"Page has ~{li_rows} table/list rows (product listing layout)")

    # --- Forum enrichment ---
    elif content_type == "forum":
        stats_parts: list[str] = []
        cnt_matches = re.findall(
            r'(\d[\d,]*)\s*(posts?|messages?|threads?|topics?|members?|users?)',
            words_text[:4000], re.IGNORECASE,
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
        a_tags = re.findall(
            r'<a[^>]*>(.*?)</a>', body_text[:16384], re.IGNORECASE | re.DOTALL,
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
            # Use topic titles directly (no translation)
            _add(f"Topic threads seen: {'; '.join(topics)}")

    # --- Blog enrichment ---
    elif content_type == "blog":
        if any(s in lower_body for s in ["rss", "atom.xml", "<?xml", "<feed"]):
            _add("RSS/Atom feed detected (updateable content)")

        blog_eng = {
            "Ghost": [r'ghost-'],
            "WordPress": [r'wp-content', r'wordpress'],
            "Jekyll": [r'jekyll', r'jekyll-feed'],
            "Hugo": ["hugo"],
        }
        for eng, pats in blog_eng.items():
            if any(re.search(p, lower_body) for p in pats):
                _add(f"Powered by: {eng}")
                break

        # Extract blog post titles from article/headings
        a_tags = re.findall(
            r'<a[^>]*>(.*?)</a>', body_text[:16384], re.IGNORECASE | re.DOTALL,
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
            # Use post titles directly (no translation)
            _add(f"Recent posts: {'; '.join(posts)}")

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
            e for e in re.findall(r'\.([a-z]{2,6})\b', lower_body[:16384])
            if e in KNOWN_EXTS
        ))[:10]
        if exts:
            _add(f"File types present: {', '.join(exts)}")

    # --- Search engine enrichment ---
    elif content_type == "search engine":
        result_count = re.search(r'(\d[\d,]*)\s*(?:results?|pages? indexed)', words_text[:2000], re.IGNORECASE)
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

    # --- Common footer info ---
    if tech_stack:
        _add(f"Tech stack: {', '.join(tech_stack)}")
    elif spa_framework:
        _add(f"SPA framework: {spa_framework}")

    n_links = len(linked_sites)
    if n_links:
        _add(f"Found {n_links} linked i2p site(s)")

    # Fallback: if summary has almost nothing, grab first body text block
    if len(lines) <= 1 and words_text:
        first_block = " ".join(words_text.split()[:50])
        if len(first_block) > 20:
            _add(f"Body text: \"{first_block[:300]}\"")

    return content_type, lines, linked_sites


# Register via the decorator so it appears in the auto-discovery scan
from src.extractors import _register  # noqa: E402

_register(HtmlExtractor)
