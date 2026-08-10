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
import pathlib
import re
import tempfile
import textwrap
import time
from collections import Counter
from html.parser import HTMLParser
from typing import Any, Dict, List, NamedTuple

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

_FRAMEWORK_SIGNATURES = [
    ('WordPress', ('/wp-content/', '/wp-includes/')),
    ('Drupal', ('drupalSettings', 'views-view')),
    ('Joomla', ('/components/com_', 'tmpl=component')),
    ('phpBB', ('Powered by phpBB', 'posting.php')),
    ('SMF', ('Simple Machines Forum', '/Themes/')),
    ('Discourse', ('preloaded-user', 'ember-auto-id')),
    ('phpMyAdmin', ('pma__', 'server_variables')),
    ('Nextcloud', ('/apps/activity/', 'settings-jar')),
    ('ownCloud', ('data-owner=', 'oc-core')),
]


def _detect_fingerprints(body_sample: str) -> Dict[str, List[str]]:
    """Analyze HTML body for framework signatures, meta tags, and structure."""
    from html.parser import HTMLParser

    results = {
        "frameworks": [],
        "meta_tags": [],
        "structural": [],
        "content_types": [],
    }

    body_lc = body_sample.lower()
    html_len = len(body_sample)

    for fw_name, keywords in _FRAMEWORK_SIGNATURES:
        matched = [k for k in keywords if k.lower() in body_lc]
        if matched:
            results["frameworks"].append((fw_name, matched))

    class MetaExtract(HTMLParser):
        def __init__(self):
            super().__init__()
            self.metas = []
        def handle_starttag(self, tag, attrs):
            if tag != "meta":
                return
            ad = {k.lower(): v for k, v in attrs if k}
            gen = ad.get("generator", "")
            author = ad.get("author", "")
            appn = ad.get("application-name", "")
            if gen:
                self.metas.append(("generator", gen))
            elif author:
                self.metas.append(("author", author[:64]))
            elif appn:
                self.metas.append(("app_name", appn[:64]))

    if "<meta" in body_lc:
        try:
            mx = MetaExtract()
            mx.feed(body_sample[:min(int(html_len * 0.15), 4096)])
            for mt, mv in mx.metas:
                results["meta_tags"].append((mt, mv))
        except Exception:
            pass

    if body_lc.startswith("{") or body_lc.startswith("["):
        results["content_types"].append("json_api")
    elif "<rss" in body_lc or "<feed" in body_lc:
        results["content_types"].append("xml_feed")
    elif "announce" in body_lc and "torrent" in body_lc:
        results["content_types"].append("torrent_tracker")

    if html_len > 512:
        tc = Counter()
        class TagCount(HTMLParser):
            def handle_starttag(self, tag, attrs):
                tc[tag] += 1
        try:
            x = TagCount()
            x.feed(body_sample[:4096])
            tot = sum(tc.values())
            if tot >= 5:
                tbl = tc.get("table", 0) / max(tot, 1)
                fmt = tc.get("form", 0)
                ank = tc.get("a", 0)
                if tbl > 0.25:
                    results["structural"].append(("table_heavy", f"{tbl:.0%}"))
                if fmt >= 2:
                    results["structural"].append(("form_based", str(fmt)))
                if ank > tot * 0.3:
                    results["structural"].append(("link_dense", str(ank)))
        except Exception:
            pass

    return results


_GENERATOR_TEMPLATE = '''"""Auto-generated extractor: {EXTRACTOR_NAME}.

Source: analyzer --generate (body hash: {BODY_HASH})
Fingerprints detected: {fingerprint_names}
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

from src.extractors import BaseExtractor


class {classname}(BaseExtractor):
    """Auto-generated extractor for {EXTRACTOR_NAME}."""

    priority = 80  # Runs before HtmlExtractor (priority=90)

    _KNOWN_CT = "{content_type}"

    def can_handle(
        self,
        body_text: str,
        headers: Dict[str, str],
        status_code: int,
    ) -> bool:
        """Check if response matches."""  # TODO: verify
{ct_hint}

        body_lower = body_text.lower()
        hits = 0
{fingerprint_checks}

        return hits >= 2

    def extract(
        self,
        title: str,
        body_text: str,
        headers: Dict[str, str],
    ) -> Tuple[str, List[str], List[str]]:
        """Extract structured classification."""
        import re
        lines = []
{extract_summary_lines}
        content_type = self._KNOWN_CT
        links = self._find_i2p_links(body_text)
        return content_type, lines, links

    @staticmethod
    def _find_i2p_links(body_text: str) -> list[str]:
        """Extract .i2p hostnames from body text."""
        pat = r"([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)?\.i2p)"
        return list({{h.lower() for h in re.findall(pat, body_text[:32768], re.I)}})'''


def generate_extractor_skeleton(
    sample_body: str,
    content_type_hint: str = "",
    extractor_name: str = "CustomExtractor",
) -> str:
    """Generate a BaseExtractor subclass skeleton from a sample response body.

    Analyzes the sample body to identify potential fingerprints (Content-Type
    hints, recognizable patterns in headers/body structure), detects framework
    signatures and DOM markers, and emits Python code for a new extractor plugin
    file.  The generated code defaults ``can_handle`` to require >=2 fingerprint
    matches so false positives stay conservative.

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
    body_lc = body_sample.lower()

    fingerprints = _detect_fingerprints(body_sample)

    fp_names = []
    if fingerprints["frameworks"]:
        fp_names.append(f"CMS: {[fw[0] for fw in fingerprints['frameworks']]}")
    if fingerprints["content_types"]:
        fp_names.append(f"Content type: {fingerprints['content_types']}")
    if fingerprints["structural"]:
        fp_names.append(f"Structure: {[s[0] for s in fingerprints['structural']]}")
    if not fp_names:
        fp_names.append("none detected - manual review needed")

    ct_lower = (content_type_hint or "").lower()
    detected_type = "unknown"
    if "json" in ct_lower or "json_api" in fingerprints["content_types"]:
        detected_type = "json_api"
    elif ("xml" in ct_lower and ("rss" in ct_lower or "atom" in ct_lower)) or \
         "xml_feed" in fingerprints["content_types"]:
        detected_type = "feed_rss"
    elif "announce" in body_lc and "tracker" in body_lc:
        detected_type = "torrent_tracker"
    elif "text/plain" in ct_lower:
        detected_type = "plain_text"
    elif "application/octet-stream" in ct_lower:
        detected_type = "binary"

    if fingerprints["frameworks"]:
        detected_type = fingerprints["frameworks"][0][0].lower().replace(" ", "_")

    fp_checks = []
    DQ = chr(34)

    def fp_line(check_expr, label=""):
        fp_checks.append(f'        if {check_expr}:')
        fp_checks.append(f'            hits += 1  # {label}')

    if ct_lower:
        safe_ct = ct_lower.replace("\\", "\\\\")
        fp_checks.append(f'        if "{safe_ct}" in headers.get("Content-Type", "").lower():')
        fp_checks.append('            hits += 1  # content-type')

    if body_lc.startswith("{") or body_lc.startswith("["):
        fp_line(r're.match(r"^\s*[\{\[]", body_text)', "json-start")

    if "<rss" in body_lc or "<feed" in body_lc:
        fp_line('"\\x3crss" in body_lower or "\\x3cfeed" in body_lower', "rss-feed")

    for fw_name, matched_kws in fingerprints["frameworks"]:
        kw = matched_kws[0]
        safe_kw = kw.replace(DQ, "").replace("\\", "")[:32]
        fp_line(f'"{safe_kw}" in body_lower', f"{fw_name}")

    if "announce" in body_lc and ("tracker" in body_lc or "torrent" in body_lc):
        fp_line('"announce" in body_lower or "torrent" in body_lower', "tracker")

    for struct_name, _ in fingerprints["structural"]:
        if struct_name == "table_heavy":
            fp_line('body_text.count("\\x3ctable") >= 3', "table-heavy")
        elif struct_name == "form_based":
            fp_line('body_text.count("\\x3cform") >= 2', "form-based")
        elif struct_name == "link_dense":
            fp_line('len(re.findall(r"href", body_text)) > 20', "link-dense")

    for meta_type, meta_val in fingerprints["meta_tags"]:
        safe_val = meta_val[:32].replace(DQ, "").replace("\\", "")
        fp_line(f'"{safe_val}" in body_lower', f"meta-{meta_type}")

    fp_checks.append("        # TODO: test against live samples and adjust threshold")
    # No separate ct_hint block; Content-Type is just another fingerprint check
    ct_hint_lines = []
    extract_summary = []
    extract_summary.append("        if title:")
    extract_summary.append('            lines.append(f"Title: {title}")')
    for mtype, mval in fingerprints["meta_tags"][:3]:
        safe_mv = mval.replace(DQ, "").replace("\\", "")[:40]
        extract_summary.append(
            f'        lines.append(f"Meta-{mtype}: \\"{safe_mv}\\"")  # detected'
        )

    classname = "".join(w.capitalize() for w in extractor_name.replace("-", " ").split()) + "Extractor"
    display_name = extractor_name

    code = _GENERATOR_TEMPLATE.format(
        EXTRACTOR_NAME=display_name,
        BODY_HASH=body_hash_short,
        classname=classname,
        ct_hint="\n".join(ct_hint_lines),
        fingerprint_checks="\n".join(fp_checks),
        content_type=detected_type,
        fingerprint_names=", ".join(fp_names),
        extract_summary_lines="\n".join(extract_summary),
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
# 3c. File naming + test-skeleton helpers for --out-dir
# ---------------------------------------------------------------------------


def _extractor_module_name(extractor_name: str) -> str:
    """Return the file stem for a generated extractor plugin."""
    clean = re.sub(r"[^a-zA-Z0-9]", "_", extractor_name).lower()
    clean = re.sub(r"_+", "_", clean).strip("_") or "custom"
    return f"{clean}_extractor"


def _extractor_class_name(extractor_name: str) -> str:
    """Return the class name that ``generate_extractor_skeleton`` produces."""
    return "".join(w.capitalize() for w in extractor_name.replace("-", " ").split()) + "Extractor"


def _generate_test_skeleton(
    extractor_name: str,
    sample_body: str,
) -> str:
    """Generate a minimal pytest test file for a generated extractor."""
    module = _extractor_module_name(extractor_name)
    classname = _extractor_class_name(extractor_name)
    truncated_sample = repr(sample_body[:4096])
    return (
        f'"""Tests for {module} - auto-generated alongside the extractor."""\n'
        'import pytest\n'
        'from src.extractors import BaseExtractor\n'
        '\n'
        f'from {module} import {classname}\n'
        '\n'
        '\n'
        '@pytest.fixture()\n'
        'def ext():\n'
        f'    return {classname}()\n'
        '\n'
        '\n'
        'class TestCanHandle:\n'
        '    """Positive and negative can_handle() checks."""\n'
        '\n'
        '    def test_is_registered_extractor(self, ext):\n'
        '        assert isinstance(ext, BaseExtractor)\n'
        '\n'
        '    def test_matches_sample_payload(self, ext):\n'
        '        """The same body that triggered generation should claim-match."""\n'
        f'        sample = {truncated_sample}\n'
        '        assert ext.can_handle(sample, {}, 200) is True\n'
        '\n'
        '    def test_rejects_empty_body(self, ext):\n'
        '        assert ext.can_handle("", {}, 200) is False\n'
        '\n'
        '\n'
        'class TestExtract:\n'
        '    """Basic sanity on extract()."""\n'
        '\n'
        '    def test_returns_triple(self, ext):\n'
        '        ct, lines, links = ext.extract("Title", "sample body text", {})\n'
        '        assert isinstance(ct, str)\n'
        '        assert isinstance(lines, list)\n'
        '        assert isinstance(links, list)\n'
    )


def _write_extractor_with_test(
    code: str,
    test_code: str,
    out_dir: pathlib.Path,
    extractor_name: str,
):
    """Write an extractor module and its companion test file to *out_dir*."""
    out_dir.mkdir(parents=True, exist_ok=True)
    module_name = _extractor_module_name(extractor_name)
    mod_file = out_dir / f"{module_name}.py"
    test_file = out_dir / f"test_{module_name}.py"

    try:
        with open(mod_file, "w") as f:
            f.write(code)
    except Exception as e:
        raise RuntimeError(f"Cannot write extractor to {mod_file}: {e}") from e

    try:
        with open(test_file, "w") as f:
            f.write(test_code)
    except Exception as e:
        print(
            f"  Could not write test file to {{test_file}}: {{e}}",
            file=sys.stderr,
        )

    return mod_file, test_file


# ---------------------------------------------------------------------------
# 3b. validate_extractor — runtime validation of generated plugins
# ---------------------------------------------------------------------------


def validate_extractor(
    code: str,
    sample_body: str,
    headers: Dict[str, str] | None = None,
    status_code: int = 200,
) -> Dict[str, Any]:
    """Validate a generated extractor plugin by running it against its source sample.

    Compiles the generated Python code, dynamically imports the extractor class,
    and calls ``can_handle()`` against the original sample body that triggered
    generation. If ``can_handle()`` returns False, the result includes suggested
    fixes (e.g., lowering the hit threshold, adjusting fingerprint patterns).

    Args:
        code: Python source from ``generate_extractor_skeleton()``.
        sample_body: Raw response body text used as the generation seed.
        headers: Response headers dict (default: empty).
        status_code: HTTP status code of the probe (default: 200).

    Returns:
        Dict with keys:
          - ``valid`` (bool): True if can_handle() succeeded on the sample.
          - ``class_name`` (str): Extractor class name found in generated code.
          - ``error`` (str | None): Exception message if compilation/import failed.
          - ``suggestions`` (list[str]): Recommended fixes when validation fails.
    """
    result: Dict[str, Any] = {
        "valid": False,
        "class_name": None,
        "error": None,
        "suggestions": [],
    }

    # Step 1: Syntax check
    if not _validate_syntax(code):
        result["error"] = "Generated code has syntax errors"
        result["suggestions"].append("Review fingerprints — a string literal may contain unescaped quotes")
        return result

    if headers is None:
        headers = {}

    # Step 2: Mock BaseExtractor so the generated import resolves
    try:
        import sys
        from types import ModuleType

        mock_mod = ModuleType("src.extractors")

        class _MockBase:
            priority = 50

            def can_handle(self, body_text, headers, status_code): ...
            def extract(self, title, body_text, headers): ...

        mock_mod.BaseExtractor = _MockBase

        # Save and replace
        saved_module = sys.modules.get("src.extractors")
        sys.modules["src.extractors"] = mock_mod

        namespace: Dict[str, Any] = {}
        exec(code, namespace)

        # Restore immediately
        if saved_module is not None:
            sys.modules["src.extractors"] = saved_module
        else:
            sys.modules.pop("src.extractors", None)

        # Step 3: Find the extractor class in the namespace
        extractor_cls = None
        for cls_name, obj in namespace.items():
            if (
                isinstance(obj, type)
                and hasattr(obj, "can_handle")
                and hasattr(obj, "extract")
                and cls_name != "BaseExtractor"
            ):
                extractor_cls = obj
                result["class_name"] = cls_name
                break

        if extractor_cls is None:
            result["error"] = "No extractor class found in generated code"
            result["suggestions"].append("Ensure generate_extractor_skeleton() produced a valid subclass")
            return result

        # Step 4: Run can_handle against the original sample
        instance = extractor_cls()
        matched = instance.can_handle(sample_body[:32768], headers, status_code)
        result["valid"] = matched

        if not matched:
            # Step 5: Generate suggestions for why it failed
            suggestions = _suggest_fingerprint_fixes(code, sample_body, headers)
            result["suggestions"] = suggestions

    except Exception as e:
        result["error"] = str(e)
        result["suggestions"].append("Check that the generated code is a valid BaseExtractor subclass")

    return result


def _suggest_fingerprint_fixes(
    code: str,
    sample_body: str,
    headers: Dict[str, str],
) -> List[str]:
    """Analyze why can_handle() failed and suggest concrete fixes."""
    suggestions: List[str] = []
    body_lower = sample_body.lower()

    # Check if the threshold is too high
    if "hits >= 2" in code or "hits >=3" in code:
        suggestions.append(
            "Lower the hit threshold from 'hits >= 2' to 'hits >= 1' — "
            "the sample may only trigger one fingerprint pattern"
        )

    # Check if Content-Type header was available but not used
    ct = headers.get("Content-Type", "")
    if ct and ("content-type" not in code.lower() or f'"{ct}"' not in code):
        suggestions.append(
            f"Add the actual Content-Type header as a fingerprint: \"{ct}\" — "
            "it was present in the response but not captured by can_handle()"
        )

    # Check if body is too short for the generated patterns to match
    if len(sample_body) < 100:
        suggestions.append(
            "Sample body is very short (<100 chars) — regenerate with a larger "
            "response or add structural checks that match short content"
        )

    # Check if common HTML tags exist but weren't fingerprinted
    html_tags = ["<html", "<head", "<body", "<div", "<table", "<form"]
    tag_matches = [t for t in html_tags if t in body_lower]
    if tag_matches and not any(t.replace("<", "\\x3c") in code for t in tag_matches):
        suggestions.append(
            f"Body contains HTML tags ({', '.join(tag_matches[:3])}) that could "
            "be added as additional fingerprint checks"
        )

    # Suggest re-running generation with more fingerprints
    if not suggestions:
        suggestions.append(
            "Re-run generate_extractor_skeleton() with the full response body "
            "(increase capture size) to detect more unique markers"
        )

    return suggestions


# ---------------------------------------------------------------------------
# 5. generate_extractors_pipeline — flagged → probe → generate → write
# ---------------------------------------------------------------------------


class PipelineResult(NamedTuple):
    """One row returned from the generate-for-flagged pipeline."""
    idx: int
    host: str
    status: int
    body_length: int
    code_lines: int
    valid: bool
    written_path: str
    error: str


def generate_extractors_pipeline(
    limit: int | None = None,
    timeout: float = 60.0,
    dry_run: bool = False,
    force: bool = False,
) -> List[PipelineResult]:
    """Iterate flagged destinations, probe each body, generate + validate extractor plugins.

    Workflow per destination:
        1. Fetch body via I2P proxy (dns_name preferred, fallback to b32).
         2. Use content_type hint from last probe for naming/fingerprinting.
        3. Generate extractor skeleton with ``generate_extractor_skeleton()``.
        4. Validate with ``validate_extractor()``.
        5. When dry_run=True or valid=False and not force: do not write.
        6. On success: write to ``ext_plugins/<name>_extractor.py`` and clear needs_review.

    Args:
        limit: Maximum flagged destinations to process.
        timeout: Per-target probe timeout in seconds.
        dry_run: Fetch + generate but skip writing to disk.
        force: Write even when validator says can_handle() failed.

    Returns:
        List of ``PipelineResult`` tuples with per-destination status.
    """
    from src.integration import DiscoveryDB, DEFAULT_DB_PATH
    from src.analyzer import validate_extractor

    db = DiscoveryDB(DEFAULT_DB_PATH)
    try:
        flagged = db.get_flagged_destinations_with_hints(limit=limit)
    finally:
        db.close()

    if not flagged:
        print("\n  No flagged destinations found in the database.")
        return []

    n_total = len(flagged)
    print(f"\n  Pipeline: probe → generate → validate for {n_total} destination(s)...")
    print(f"  Dry run: {'yes' if dry_run else 'no'}  |  Force write: {'yes' if force else 'no'}")
    print(f"{'─'*64}")

    # Ensure ext_plugins directory exists
    plugin_dir = pathlib.Path(__file__).parent / "ext_plugins"
    plugin_dir.mkdir(exist_ok=True)

    results: List[PipelineResult] = []

    for idx, entry in enumerate(flagged, 1):
        dns_name = entry.get("dns_name", "")
        b32_addr = entry.get("b32_addr", "")
        hint_ctype = entry.get("content_type", "")
        title = entry.get("title", "")
        hash_hex = entry["hash_hex"]

        label = dns_name if dns_name else b32_addr or hash_hex[:16]
        print(f"\n  [{idx}/{n_total}] {label}")

        # ── Build target URL: prefer DNS, fall back to b32 ──
        if dns_name and not dns_name.endswith(".b32.i2p"):
            target_url = f"http://{dns_name}"
        elif b32_addr:
            target_url = f"http://{b32_addr}"
        else:
            print(f"    SKIP — cannot derive address")
            results.append(PipelineResult(
                idx=idx, host=label, status=0, body_length=0,
                code_lines=0, valid=False, written_path="",
                error="no_address_available",
            ))
            continue

        # ── Fetch body ──
        try:
            resp = fetch_i2p(target_url, via="http-proxy", timeout=timeout)
        except Exception as e:
            print(f"    ERROR fetching: {e}")
            results.append(PipelineResult(
                idx=idx, host=label, status=0, body_length=0,
                code_lines=0, valid=False, written_path="",
                error=str(e),
            ))
            continue

        if not resp.status or not resp.body:
            print(f"    SKIP — no usable response (status={resp.status})")
            results.append(PipelineResult(
                idx=idx, host=label, status=resp.status or 0, body_length=0,
                code_lines=0, valid=False, written_path="",
                error=f"unreachable_or_empty_status_{resp.status}",
            ))
            continue

        try:
            body_text = resp.body.decode("utf-8", errors="replace") if isinstance(resp.body, bytes) else str(resp.body)
        except Exception:
            body_text = ""

        if len(body_text.strip()) < 20:
            print(f"    SKIP — body too short ({len(body_text)} chars)")
            results.append(PipelineResult(
                idx=idx, host=label, status=resp.status, body_length=len(body_text),
                code_lines=0, valid=False, written_path="",
                error="body_too_short",
            ))
            continue

        # ── Derive extractor name from hint content_type / title / dns_name ──
        if hint_ctype:
            classifier_name = re.sub(r"[^a-zA-Z0-9]", "", hint_ctype.replace(" ", "_"))
        elif title:
            words = re.split(r"[^a-zA-Z0-9]+", title.strip())[:3]
            classifier_name = "_".join(w for w in words if len(w) > 2 and not w.lower() in ("the", "and", "com", "net")).lower() or "custom"
        else:
            # Fall back to DNS short name
            base = dns_name.split(".i2p")[0].split(".")[-1] if dns_name else hash_hex[:8]
            classifier_name = re.sub(r"[^a-zA-Z0-9]", "", base)

        if not classifier_name:
            classifier_name = "custom"

        print(f"    Fetch: status={resp.status}  body={len(body_text)}B  hint={hint_ctype or '(none)'}")

        # ── Build CT hint from live response headers ──
        live_ct = ""
        if isinstance(resp.headers, dict):
            live_ct = resp.headers.get("Content-Type", "") or ""

        ct_hint = live_ct or hint_ctype or "unknown"

        # ── Generate skeleton ──
        code = generate_extractor_skeleton(
            sample_body=body_text,
            content_type_hint=ct_hint,
            extractor_name=classifier_name,
        )

        code_line_count = len(code.splitlines())
        print(f"    Generated: {code_line_count} lines  →  {classifier_name}")

        if not _validate_syntax(code):
            print(f"    ✗ Syntax error in generated code")
            results.append(PipelineResult(
                idx=idx, host=label, status=resp.status, body_length=len(body_text),
                code_lines=code_line_count, valid=False, written_path="",
                error="syntax_error_in_generated_code",
            ))
            continue

        # ── Validate against the sample body ──
        header_dict = resp.headers if isinstance(resp.headers, dict) else {}
        result = validate_extractor(code, body_text, header_dict, resp.status)

        valid = result["valid"]
        print(f"    Can handle validation: {'✓' if valid else '✗'}")
        if not valid and result.get("suggestions"):
            for s in result["suggestions"]:
                print(f"      → {s}")

        # ── Should we write? ──
        should_write = (valid or force) and not dry_run
        written_path = ""

        if should_write:
            file_name = f"{classifier_name}_extractor.py"
            out_path = plugin_dir / file_name

            # Check for existing extractor with same name — don't overwrite unless --force explicitly
            if out_path.exists() and not force:
                print(f"    SKIP — {file_name} already exists (use --force to overwrite)")
                results.append(PipelineResult(
                    idx=idx, host=label, status=resp.status, body_length=len(body_text),
                    code_lines=code_line_count, valid=valid, written_path="",
                    error="file_already_exists",
                ))
                continue

            try:
                with open(out_path, "w") as f:
                    f.write(code)
                written_path = str(out_path)
                print(f"    Written to {out_path.name}")

                # Clear needs_review flag if valid
                if valid:
                    db2 = DiscoveryDB(DEFAULT_DB_PATH)
                    try:
                        db2.clear_needs_review(hash_hex)
                        print(f"    Cleared needs_review for {label}")
                    finally:
                        db2.close()
            except Exception as e:
                print(f"    ERROR writing file: {e}")
                results.append(PipelineResult(
                    idx=idx, host=label, status=resp.status, body_length=len(body_text),
                    code_lines=code_line_count, valid=valid, written_path="",
                    error=f"write_error: {e}",
                ))
                continue

        else:
            if dry_run:
                print(f"    DRY RUN — would write to {classifier_name}_extractor.py")
            elif not valid:
                print(f"    SKIP — validation failed (use --force to write anyway)")

        results.append(PipelineResult(
            idx=idx, host=label, status=resp.status, body_length=len(body_text),
            code_lines=code_line_count, valid=valid, written_path=written_path,
            error="" if (valid or force) and not dry_run else result.get("error", "validation_failed"),
        ))

    print(f"\n{'='*64}")
    success = sum(1 for r in results if r.valid and r.written_path)
    written = sum(1 for r in results if r.written_path)
    errors = sum(1 for r in results if r.error)
    print(f"  Pipeline complete: {len(results)} processed")
    print(f"    Valid & written: {success}  |  Written (forced): {written}  |  Errors: {errors}")
    print(f"{'='*64}\n")

    return results


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
    gen_p.add_argument("--validate", action="store_true", help="Validate generated code at runtime against the sample body")
    gen_p.add_argument("--out", type=str, default="", help="Write extractor to a single file instead of stdout")
    gen_p.add_argument(
        "--out-dir",
        type=str,
        default="",
        help=(
            "Directory to write the generated extractor module and companion test file. "
            "Defaults to src/ext_plugins/ inside this project when omitted."
        ),
    )
    # ── all-flagged (wired → generate pipeline) ──
    af_p = sub.add_parser(
        "all-flagged",
        help="Probe flagged destinations → generate extractor plugins "
             "(default: dry-run preview; use --confirm to write)",
    )
    af_p.add_argument("--limit", type=int, default=None, help="Max destinations to process (default: all)")
    af_p.add_argument("--timeout", type=float, default=60.0, help="Per-target timeout in seconds (default: 60)")
    af_p.add_argument("--dry-run", action="store_true", help="(default) Preview without writing files")
    af_p.add_argument("--confirm", action="store_true", help="Write generated extractors to disk and clear flags")
    af_p.add_argument("--force", action="store_true", help="Write even if validation fails")

    # ── generate-for-flagged (legacy alias for all-flagged --confirm) ──
    gff_p = sub.add_parser("generate-for-flagged", help="[deprecated] Alias for all-flagged --confirm")
    gff_p.add_argument("--limit", type=int, default=None, help="Max destinations to process (default: all)")
    gff_p.add_argument("--timeout", type=float, default=60.0, help="Per-target timeout in seconds (default: 60)")
    gff_p.add_argument("--dry-run", action="store_true", help="Generate but don't write to disk")
    gff_p.add_argument("--force", action="store_true", help="Write even if validation fails")

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
        from src.analyzer import validate_extractor

        code = generate_extractor_skeleton(
            sample_body=args.body,
            content_type_hint=getattr(args, "content_type", getattr(args, "content-type", "")),
            extractor_name=args.name,
        )
        if _validate_syntax(code):
            print("  ✓ Generated code passes syntax check")
        else:
            print("  ✗ Generated code has syntax errors (please review)", file=sys.stderr)

        # Runtime validation against the sample body
        if getattr(args, "validate", False):
            result = validate_extractor(code, args.body, {})
            if result["valid"]:
                print(f"  ✓ Runtime validation PASSED — can_handle() matched the sample body")
                print(f"    Class: {result['class_name']}")
            else:
                print("  ✗ Runtime validation FAILED — can_handle() did NOT match the sample body", file=sys.stderr)
                if result.get("error"):
                    print(f"    Error: {result['error']}", file=sys.stderr)
                for s in result.get("suggestions", []):
                    print(f"    → {s}", file=sys.stderr)

        out_path = getattr(args, "out", "") or ""
        out_dir_str = getattr(args, "out_dir", getattr(args, "out-dir", "")) or ""

        if out_dir_str:
            # --out-dir: resolve relative to project root (parent of src/)
            out_dir = pathlib.Path(out_dir_str)
            if not out_dir.is_absolute():
                out_dir = pathlib.Path(__file__).parent.parent / out_dir
            test_code = _generate_test_skeleton(args.name, args.body)
            mod_file, test_file = _write_extractor_with_test(
                code, test_code, out_dir, args.name
            )
            print(f"  Written extractor → {mod_file}")
            print(f"  Written test     → {test_file}")
        elif out_path:
            with open(str(out_path), "w") as f:
                f.write(code)
            print(f"  Written to {out_path}")
        else:
            print()
            print(code)

    elif args.command == "all-flagged":
        # Default: dry-run preview unless --confirm passed explicitly
        dry = not getattr(args, "confirm", False) and not getattr(args, "dry_run", False)
        # If neither --confirm nor --dry-run given → dry run by default
        if getattr(args, "confirm", False):
            dry = False
        elif getattr(args, "dry_run", False):
            dry = True
        else:
            dry = True

        generate_extractors_pipeline(
            limit=args.limit,
            timeout=args.timeout,
            dry_run=dry,
            force=getattr(args, "force", False),
        )

    elif args.command == "generate-for-flagged":
        # Legacy alias — behaves like all-flagged --confirm (unless --dry-run)
        generate_extractors_pipeline(
            limit=args.limit,
            timeout=args.timeout,
            dry_run=getattr(args, "dry_run", False),
            force=getattr(args, "force", False),
        )


if __name__ == "__main__":
    main()
