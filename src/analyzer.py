"""Analyzer — deep inspection tool for flagged destinations.

When an extractor fails to classify a destination, the system flags it with
``needs_review=True`` so a human (or this analyzer) can dig deeper.  The
analyzer provides four subcommands:

1. ``fetch-all-paths`` — try common paths on a host and report what responds
2. ``inspect-headers`` — dump all HTTP headers from the first successful probe
3. ``generate``         — generate a starter ``BaseExtractor`` subclass for the
                          given response body so specialists can build one fast
4. ``all-flagged``      — iterate every flagged destination and run inspection

Usage::

    python -m src.analyzer inspect-headers --b32 <addr>
    python -m src.analyzer fetch-all-paths --b32 <addr>
    python -m src.analyzer generate --body "json or raw body text"
    python -m src.analyzer all-flagged [--limit 10] [--timeout 60]
"""
from __future__ import annotations

import sys
sys.path.insert(0, ".")

import argparse
import inspect
import json
import logging
import tempfile
import textwrap
import time
from typing import Dict, List, Any

from src.i2p_proxy import fetch_i2p, Response

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Common set of paths to try
# ---------------------------------------------------------------------------

COMMON_PATHS = [
    "/",
    "/index.html",
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/.well-known/dnt-policy.txt",
    "/admin/",
    "/login",
    "/wp-login.php",
    "/api/",
    "/api/v1/",
    "/feed",
    "/rss",
    "/atom.xml",
    "/contact",
]

# ---------------------------------------------------------------------------
# 1. fetch_all_paths — try paths on a target host
# ---------------------------------------------------------------------------


def _fetch_path(url: str, timeout: float = 15.0) -> Dict[str, Any]:
    """Fetch a single path and return structured result."""
    t0 = time.monotonic()
    try:
        resp = fetch_i2p(url, via="http-proxy", timeout=timeout)
        elapsed = round(time.monotonic() - t0, 3)
        body_len = len(resp.body) if resp.body else 0
        return {
            "url": url,
            "status": resp.status,
            "body_length": body_len,
            "content_type": resp.headers.get("Content-Type", ""),
            "elapsed_sec": elapsed,
            "via_": resp.via.value if hasattr(resp, "via") else "",
        }
    except Exception as e:
        return {
            "url": url,
            "status": 0,
            "error": str(e),
            "elapsed_sec": round(time.monotonic() - t0, 3),
        }


def fetch_all_paths(
    host: str,
    paths: List[str] | None = None,
    timeout: float = 15.0,
) -> List[Dict[str, Any]]:
    """Try a set of paths on an I2P host and report which ones respond.

    Args:
        host: The ``.i2p`` hostname (without trailing slash).
        paths: List of path strings to try. Defaults to COMMON_PATHS.
        timeout: Per-path fetch timeout in seconds.

    Returns:
        List of result dicts with status code, body_length, content_type.
    """
    if paths is None:
        paths = COMMON_PATHS

    base = f"http://{host}" if not host.startswith("http") else host.rstrip("/")
    results = []
    for path in paths:
        url = f"{base}{path}"
        result = _fetch_path(url, timeout=timeout)
        results.append(result)
        logger.info(
            "  %-40s -> %d  (%d bytes)",
            path,
            result.get("status", 0),
            result.get("body_length", 0),
        )
    return results


def print_fetch_paths(results: List[Dict[str, Any]]) -> None:
    """Pretty-print fetch_all_paths results."""
    print(f"\n{'─'*72}")
    print(f"  {'Path':<42} {'Status':>6}  {'Size':>8}  {'Content-Type'}")
    print(f"  {'─'*42}  {'─'*6}  {'─'*8}  {'─'*20}")
    for r in results:
        status = r.get("status", 0) or "ERR"
        size = r.get("body_length", "?") or "?"
        ct = (r.get("content_type") or "")[:40]
        path = r.get("url", "").rsplit("/", 1)[-1] if "/" in r.get("url", "") else r.get("url", "")
        print(f"  {path:<42}  {status:>6}  {size:>8}  {ct}")
    print(f"{('─'*72)}\n")


# ---------------------------------------------------------------------------
# 2. inspect_headers — dump ALL headers from a probe
# ---------------------------------------------------------------------------


def inspect_headers(
    host: str,
    timeout: float = 30.0,
) -> Response | None:
    """Fetch the root path of an I2P host and return full Response with headers.

    Args:
        host: The ``.i2p`` hostname.
        timeout: Fetch timeout in seconds.

    Returns:
        Response object (always created, even on failure).
    """
    url = f"http://{host}" if not host.startswith("http") else host.rstrip("/") + "/"
    logger.info(f"  Inspecting headers for {url}")
    resp = fetch_i2p(url, via="http-proxy", timeout=timeout)
    return resp


def print_headers(resp: Response | None) -> None:
    """Pretty-print a Response showing all details."""
    if resp is None:
        print("  No response to display.")
        return
    print(f"\n{'─'*72}")
    print(f"  URL        : {resp.url}")
    print(f"  Status     : {resp.status}")
    print(f"  Size       : {len(resp.body)} bytes")
    print(f"  Encoding   : {resp.encoding}")
    print(f"  Via        : {resp.via.value if hasattr(resp, 'via') and resp.via else 'unknown'}")
    print(f"  Elapsed    : {resp.elapsed:.3f}s")
    title = resp.title()
    if title:
        print(f"  Title      : {title[:80]}")
    print(f"\n  {'Headers':->52}")
    print(f"  {'─'*52}")
    headers = dict(resp.headers) if isinstance(resp.headers, dict) else {}
    for k, v in sorted(headers.items()):
        print(f"  {k:<30} : {v}")
    if not headers:
        print("  (no headers)")
    body_preview = resp.text[:512]
    if body_preview.strip():
        print(f"\n  {'Body Preview':->52}")
        print(f"  {'─'*52}")
        for line in body_preview.splitlines()[:10]:
            print(f"  {line[:80]}")
    print(f"{('─'*72)}\n")


# ---------------------------------------------------------------------------
# 3. generate — produce a BaseExtractor subclass skeleton from sample body
# ---------------------------------------------------------------------------


_GENERATOR_TEMPLATE = '''\
"""Auto-generated extractor for: EXTRACTOR_NAME.

Source: analyzer --generate (body hash: BODY_HASH)
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

from src.extractors import BaseExtractor


class {classname}(BaseExtractor):
    \"\"\"Auto-generated extractor for EXTRACTOR_NAME.\"\"\"

    priority = 80  # Runs before HtmlExtractor (priority=90)

    def can_handle(
        self,
        body_text: str,
        headers: Dict[str, str],
        status_code: int,
    ) -> bool:
        \\\"\\\"\\\"Check if response matches this content type.\\\"\\\"\\\"  # TODO: refine fingerprints
{ct_hint}

        # Body fingerprint checks (TODO: verify against actual samples)
        body_lower = body_text.lower()
{fingerprint_checks}
        return False  # Change to True once fingerprint is validated

    def extract(
        self,
        title: str,
        body_text: str,
        headers: Dict[str, str],
    ) -> Tuple[str, List[str], List[str]]:  # type: ignore[override]
        \"\"\"Extract structured classification.\"\"\"
        import re

        lines = []
        if title:
            lines.append(f"Title: {{title}}")

        # TODO: Add specific extraction logic here

        content_type = "{content_type}"
        links = self._find_i2p_links(body_text)

        return content_type, lines, links

    @staticmethod
    def _find_i2p_links(body_text: str) -> list[str]:
        \"\"\"Extract .i2p hostnames from body text.\"""
        pattern = r"([a-z0-9](?:[a-z0-9\\-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9\\-]*[a-z0-9])?)*\\.i2p)"
        return list({{h.lower() for h in re.findall(pattern, body_text[:32768], re.IGNORECASE)}})
'''


def generate_extractor_skeleton(
    sample_body: str,
    content_type_hint: str = "",
    extractor_name: str = "CustomExtractor",
) -> str:
    """Generate a BaseExtractor subclass skeleton from a sample response body.

    Analyzes the sample body to identify potential fingerprints (Content-Type
    hints, recognizable patterns in headers/body structure) and emits Python
    code for a new extractor plugin file.  The generated code is intentionally
    conservative — ``can_handle`` defaults to ``False`` so it must be reviewed
    before being useful.

    Args:
        sample_body: Raw response body text (first ~8KB used for fingerprints).
        content_type_hint: Optional Content-Type header value to guide naming.
        extractor_name: Class name for the generated extractor.

    Returns:
        Python source code string for the new extractor module.
    """
    import hashlib

    body_sample = sample_body[:8192]
    body_hash_short = hashlib.sha256(body_sample.encode(errors="replace")).hexdigest()[:12]

    # Detect content type hints from headers/body
    ct_lower = (content_type_hint or "").lower()
    detected_type = "unknown"
    if "json" in ct_lower:
        detected_type = "json_api"
    elif "xml" in ct_lower and ("rss" in ct_lower or "atom" in ct_lower):
        detected_type = "feed_rss"
    elif "text/plain" in ct_lower:
        detected_type = "plain_text"
    elif "application/octet-stream" in ct_lower:
        detected_type = "binary"

    # Look for body fingerprints
    body_lc = body_sample.lower()
    hints_lines = []

    # Content-Type header hint
    if ct_lower:
        hints_lines.append(f'        if "{ct_lower}" in headers.get("Content-Type", "").lower():')
        hints_lines.append("            return True")
        ct_hint_text = "\n".join(hints_lines)
    else:
        ct_hint_text = ""

    # Body structural fingerprints (find recognizable patterns)
    fp_checks = []

    if body_lc.startswith("{") or body_lc.startswith("["):
        fp_checks.append('        if re.match(r"^\\s*[\\{\\[]", body_text):')
        fp_checks.append("            return True")

    if "<rss" in body_lc or "<feed" in body_lc:
        fp_checks.append('        if "<rss" in body_lower or "<feed" in body_lower:')
        fp_checks.append("            return True")

    if "tracker" in body_lc and ("torrent" in body_lc or "announce" in body_lc):
        fp_checks.append('        if "tracker" in body_lower and "announce" in body_lower:')
        fp_checks.append("            return True")

    # TODO markers
    fp_checks.append('        # TODO: add more fingerprints specific to this content type')

    fingerprint_text = "\n".join(fp_checks)

    classname = "".join(word.capitalize() for word in extractor_name.replace("-", " ").split()) + "Extractor"
    display_name = extractor_name

    code = _GENERATOR_TEMPLATE.format(
        EXTRACTOR_NAME=display_name,
        BODY_HASH=body_hash_short,
        classname=classname,
        ct_hint=ct_hint_text,
        fingerprint_checks=fingerprint_text,
        content_type=detected_type,
    )
    return code


def _validate_syntax(code: str) -> bool:
    """Check if generated code has valid Python syntax."""
    try:
        compile(code, "<generated>", "exec")
        return True
    except SyntaxError:
        return False


# ---------------------------------------------------------------------------
# 4. all_flagged — iterate flagged destinations from DB
# ---------------------------------------------------------------------------


def inspect_all_flagged(
    limit: int | None = None,
    timeout: float = 60.0,
) -> List[Dict[str, Any]]:
    """Iterate every flagged destination and run a basic header inspection.

    Queries the address_book view for needs_review=1 entries, fetches each
    via its b32 address (or dns_name if available), and returns structured
    results showing status + headers for every one.

    Args:
        limit: Maximum number of flagged destinations to inspect.
        timeout: Per-target probe timeout in seconds.

    Returns:
        List of result dicts with hash, host, status, headers, etc.
    """
    from src.integration import DiscoveryDB, DEFAULT_DB_PATH

    db = DiscoveryDB(DEFAULT_DB_PATH)
    try:
        flagged = db.get_flagged_destinations(limit=limit)
    finally:
        db.close()

    if not flagged:
        print("\n  No flagged destinations found in the database.")
        return []

    n_total = len(flagged)
    print(f"\n  Analyzing {n_total} flagged destination(s)...")
    print(f"{'─'*64}")

    results = []
    for idx, (hash_hex, dns_name) in enumerate(flagged, 1):
        host = dns_name or ""
        label = hash_hex[:12] + "..."
        print(f"\n  [{idx}/{n_total}] {label} {host}")

        # Determine target URL
        if host:
            target_url = f"http://{host}"
        else:
            # If we only have hash, construct b32 address via integration module
            from src.addressbook import _hex_to_b32_addr
            try:
                b32 = _hex_to_b32_addr(hash_hex)
                target_url = f"http://{b32}"
            except Exception:
                print(f"    Cannot derive b32 address from hash")
                results.append({
                    "hash": hash_hex[:16],
                    "host": host,
                    "status": 0,
                    "error": "cannot_derive_address",
                })
                continue

        try:
            resp = fetch_i2p(target_url, via="http-proxy", timeout=timeout)
            body_len = len(resp.body) if resp.body else 0
            title_str = ""
            try:
                t = resp.title()
                title_str = t or "" if t else ""
            except Exception:
                title_str = ""

            header_count = len(resp.headers) if isinstance(resp.headers, dict) else 0
            ct_header = (resp.headers.get("Content-Type", "") if isinstance(resp.headers, dict) else "") or ""

            results.append({
                "hash": hash_hex[:16],
                "host": host,
                "status": resp.status,
                "body_length": body_len,
                "title": title_str[:80],
                "content_type": ct_header[:60],
                "header_count": header_count,
            })
            print(f"    Status: {resp.status}  Size: {body_len}B  Headers: {header_count}")

        except Exception as e:
            print(f"    ERROR: {e}")
            results.append({
                "hash": hash_hex[:16],
                "host": host,
                "status": 0,
                "error": str(e),
            })

    print(f"\n{'='*64}")
    print(f"  Analysis complete: {len(results)} destination(s) inspected")
    print(f"{'='*64}\n")
    return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point for the analyzer tool."""
    import argparse

    p = argparse.ArgumentParser(
        description="I2P Indexer Analyzer — deep inspection of flagged destinations"
    )
    sub = p.add_subparsers(dest="command")

    # ── inspect-headers ──
    ih_p = sub.add_parser("inspect-headers", help="Dump all HTTP headers from a target URL")
    ih_p.add_argument("--host", type=str, required=True, help="The .i2p hostname or full URL to inspect")
    ih_p.add_argument("--timeout", type=float, default=30.0, help="Fetch timeout in seconds (default: 30)")

    # ── fetch-all-paths ──
    fa_p = sub.add_parser("fetch-all-paths", help="Try common paths on a host and report responses")
    fa_p.add_argument("--host", type=str, required=True, help="The .i2p hostname to probe")
    fa_p.add_argument("--paths", nargs="*", default=None, help="Custom paths to try (default: built-in list)")
    fa_p.add_argument("--timeout", type=float, default=15.0, help="Per-path timeout in seconds (default: 15)")
    fa_p.add_argument("--json", action="store_true", help="Output as JSON instead of pretty table")

    # ── generate ──
    gen_p = sub.add_parser("generate", help="Generate a BaseExtractor subclass skeleton from sample body text")
    gen_p.add_argument("--body", type=str, required=True, help='Sample response body (pass raw or use -b "..."')
    gen_p.add_argument("--content-type", type=str, default="", help="Content-Type header hint for naming")
    gen_p.add_argument(
        "--name",
        type=str,
        default="custom",
        help="Classifier name (used for class naming)",
    )
    gen_p.add_argument("--validate", action="store_true", help="Validate generated code syntax and exit")
    gen_p.add_argument("--out", type=str, default="", help="Write to file instead of stdout")

    # ── all-flagged ──
    af_p = sub.add_parser("all-flagged", help="Inspect every flagged destination in the database")
    af_p.add_argument("--limit", type=int, default=None, help="Max destinations to check (default: all)")
    af_p.add_argument("--timeout", type=float, default=60.0, help="Per-target timeout in seconds (default: 60)")

    args = p.parse_args()

    if not args.command:
        p.print_help()
        sys.exit(1)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    if args.command == "inspect-headers":
        resp = inspect_headers(args.host, timeout=args.timeout)
        print_headers(resp)

    elif args.command == "fetch-all-paths":
        results = fetch_all_paths(args.host, paths=args.paths, timeout=args.timeout)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print_fetch_paths(results)

    elif args.command == "generate":
        code = generate_extractor_skeleton(
            sample_body=args.body,
            content_type_hint=getattr(args, "content_type", getattr(args, "content-type", "")),
            extractor_name=args.name,
        )
        if _validate_syntax(code):
            print("  ✓ Generated code passes syntax check")
        else:
            print("  ✗ Generated code has syntax errors (please review)", file=sys.stderr)

        out_path = getattr(args, "out", "") or ""
        if out_path:
            with open(str(out_path), "w") as f:
                f.write(code)
            print(f"  Written to {out_path}")
        else:
            print()
            print(code)

    elif args.command == "all-flagged":
        inspect_all_flagged(limit=args.limit, timeout=args.timeout)


if __name__ == "__main__":
    main()
