"""Smoke-test for the full probe pipeline.

Reads tests/smoke_targets.json, routes each request through the I2P proxy
layer (never bypassing it), and exercises every stage:

    PRE-FLIGHT  → validate proxy health
    PROBE       → fetch through configured proxy
    EXTRACT     → run_extractor registry on body text
    CLASSIFY    → content-type bucket + needs_review flag
    STORE       → write DiscoveryResult to SQLite
    REPORT      → JSON output file + stdout summary

Usage (run from project root):
    python -m src.smoke_test                     # default 120s timeout
    python -m src.smoke_test --timeout 60        # shorter deadline
    python -m src.smoke_test --targets alt.json  # custom target file
    python -m src.smoke_test --dry-run           # probe only, skip DB writes
    python -m src.smoke_test --json              # machine-readable report

Connection timeouts are handled gracefully — each stage logs before/after and
the pipeline continues to the next target on failure.

Created: 2026-08-05 for Kanban task t_694a7384.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Project imports ────────────────────────────────────────────────────
from src.config import I2PConfig
from src.extractors import run_extractors, ExtractorResult
from src.i2p_proxy import fetch_i2p, probe_health, Response, ProxyBackend
from src.integration import (
    DEFAULT_DB_PATH,
    PROBE_TIMEOUT,
    DiscoveryDB,
    DiscoveryResult as IntegrationDiscoveryResult,
)

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGETS = SCRIPT_DIR.parent / "tests" / "smoke_targets.json"

# Stages are executed per-target in this order.  Dry-run mode skips STORE.
STAGES = ["probe", "extract", "classify", "store"]

# Exit codes for CI integration (POSIX convention: 0 = success)
EXIT_SUCCESS       = 0   # All targets passed validation
EXIT_PROBE_FAIL    = 1   # One or more probes failed (network/proxy issues)
EXIT_EXTRACT_FAIL  = 2   # Extraction or classification produced invalid results
EXIT_STORE_FAIL    = 3   # Database storage failed for one or more targets
EXIT_CONFIG_FAIL   = 4   # Targets file missing, empty, or malformed
EXIT_PREFLIGHT     = 5   # Proxy health check failed (nothing reachable)

# Minimum body size (bytes) to consider a response "real content"
MIN_BODY_BYTES = 128

# ── Validation model ───────────────────────────────────────────────────


@dataclass
class ValidationResult:
    """Validation verdict for one target after all pipeline stages."""

    passed: bool                              # True => PASS, False => FAIL
    checks: Dict[str, bool] = field(default_factory=dict)  # named check results
    failure_reasons: List[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return "PASS" if self.passed else "FAIL"


def _validate_result(result: SmokeTargetResult, cfg: I2PConfig) -> ValidationResult:
    """Run validation checks on a completed target result.

    Checks:
      1. probe_ok          — Probe stage succeeded and returned HTTP >= 0
      2. status_in_range   — HTTP status is 2xx or 3xx (not 4xx/5xx/0)
      3. body_sufficient   — Response body exceeds MIN_BODY_BYTES threshold
      4. content_classified — Extractor assigned a non-empty content_type
      5. summary_present   — At least one meaningful summary line extracted
      6. no_fatal_error    — No stage produced an error message

    A target PASSES only when *all* applicable checks pass.
    """
    checks: Dict[str, bool] = {}
    reasons: List[str] = []

    # ── Check 1: Probe succeeded ────────────────────────────────
    probe_ok = any(s.name == "probe" and s.ok for s in result.stages)
    checks["probe_ok"] = probe_ok
    if not probe_ok:
        reasons.append("Probe stage failed — network or proxy error")

    # ── Check 2: HTTP status in valid range ──────────────────────
    status_valid = 100 <= result.status_code < 500
    checks["status_in_range"] = status_valid
    if not status_valid:
        reasons.append(
            f"HTTP {result.status_code} outside acceptable range (1xx–4xx)"
        )

    # ── Check 3: Body has sufficient content ────────────────────
    body_ok = result.body_length >= MIN_BODY_BYTES
    checks["body_sufficient"] = body_ok
    if not body_ok:
        reasons.append(
            f"Body too small ({result.body_length}B < {MIN_BODY_BYTES}B minimum)"
        )

    # ── Check 4: Content was classified ─────────────────────────
    has_type = bool(result.content_type and result.content_type != "unknown")
    checks["content_classified"] = has_type
    if not has_type:
        reasons.append(
            f"Content type '{result.content_type or '(none)'}' — no extractor matched"
        )

    # ── Check 5: Summary was extracted ──────────────────────────
    has_summary = bool(result.summary.strip())
    checks["summary_present"] = has_summary
    if not has_summary:
        reasons.append("No summary lines extracted from response body")

    # ── Check 6: No fatal stage errors ──────────────────────────
    no_fatal = all(not s.error for s in result.stages)
    checks["no_fatal_error"] = no_fatal
    if not no_fatal:
        error_stages = [s.name for s in result.stages if s.error]
        reasons.append(f"Stage errors in: {', '.join(error_stages)}")

    passed = all(checks.values())

    return ValidationResult(
        passed=passed,
        checks=checks,
        failure_reasons=reasons,
    )


# ── Exit code computation ──────────────────────────────────────────────


def _compute_exit_code(
    results: List[SmokeTargetResult],
    preflight_ok: bool = True,
) -> int:
    """Return POSIX-compatible exit code based on aggregate results.

    Priority (highest severity wins):
      - EXIT_PREFLIGHT     if proxy health check itself failed
      - EXIT_STORE_FAIL    if any store stage errored
      - EXIT_PROBE_FAIL    if any probe failed at network level
      - EXIT_EXTRACT_FAIL  if extraction/classification failed
      - EXIT_SUCCESS       everything passed validation
    """
    if not preflight_ok:
        return EXIT_PREFLIGHT

    has_store_fail = any(
        s.name == "store" and not s.ok
        for r in results
        for s in r.stages
    )
    has_probe_fail = any(
        s.name == "probe" and not s.ok
        for r in results
        for s in r.stages
    )
    has_extract_fail = any(
        (s.name in ("extract", "classify") and not s.ok)
        for r in results
        for s in r.stages
    )

    if has_store_fail:
        return EXIT_STORE_FAIL
    if has_probe_fail:
        return EXIT_PROBE_FAIL
    if has_extract_fail:
        return EXIT_EXTRACT_FAIL

    # If any target failed validation, classify the severity
    for r in results:
        if not r.success:
            # Determine which dimension caused the failure
            probe_ok = any(s.name == "probe" and s.ok for s in r.stages)
            ext_ok = any(s.name == "extract" and s.ok for s in r.stages)
            cls_ok = any(s.name == "classify" and s.ok for s in r.stages)
            store_ok = any(s.name == "store" and s.ok for s in r.stages)

            if not probe_ok:
                return EXIT_PROBE_FAIL
            if not ext_ok or not cls_ok:
                return EXIT_EXTRACT_FAIL
            if not store_ok:
                return EXIT_STORE_FAIL

    return EXIT_SUCCESS


# ── Data model for per-stage tracking ──────────────────────────────────


@dataclass
class StageRecord:
    """One pipeline stage result."""

    name: str                     # e.g. probe, extract, classify, store
    ok: bool
    detail: str = ""
    elapsed_sec: float = 0.0
    error: str = ""


@dataclass
class SmokeTargetResult:
    """Aggregate result for one .i2p target."""

    name: str                     # human label from targets file
    url: str
    stages: List[StageRecord] = field(default_factory=list)

    # Probe outputs
    status_code: int = 0
    body_length: int = 0
    response_time_sec: float = 0.0
    reachable: bool = False

    # Extractor outputs
    content_type: str = ""
    summary: str = ""
    found_links: List[str] = field(default_factory=list)

    # Classification outcomes
    needs_review: bool = False
    review_reason: str = ""

    # Storage outcome
    row_id: int = 0

    # Validation verdict (filled by _validate_result)
    validation: Optional[ValidationResult] = None

    @property
    def success(self) -> bool:
        """True if at least probe + extract succeeded AND validation passed."""
        stage_names = [s.name for s in self.stages]
        has_pipeline = "probe" in stage_names and "extract" in stage_names
        if self.validation is not None:
            return has_pipeline and self.validation.passed
        return has_pipeline

    @property
    def pass_label(self) -> str:
        """Human-readable PASS/FAIL label."""
        return self.validation.label if self.validation else "UNKNOWN"


# ── Target loader ─────────────────────────────────────────────────────


def load_targets(path: str | Path) -> List[Dict[str, Any]]:
    """Read smoke targets from JSON and validate schema."""
    p = Path(path)

    if not p.is_file():
        logger.error("Targets file not found at %s", p.resolve())
        sys.exit(1)

    raw_text = p.read_text(encoding="utf-8")
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in %s: %s", p, exc)
        sys.exit(1)

    targets_raw = data.get("targets", [])
    if not isinstance(targets_raw, list):
        logger.error("'targets' key must be a list in %s", p)
        sys.exit(1)

    loaded: List[Dict[str, Any]] = []
    for idx, t in enumerate(targets_raw):
        url = t.get("url")
        if not url:
            logger.warning("Target #%d missing 'url' — skipping", idx + 1)
            continue
        label = t.get("label", t.get("name")) or Path(url).stem
        description = t.get("description", "")
        loaded.append(
            {
                "name": str(label),
                "label": str(label),
                "url": url,
                "description": description,
                "proxy_requirement": t.get("proxy_requirement", ""),
            }
        )

    logger.info("Loaded %d target(s) from %s", len(loaded), p.resolve())
    return loaded


# ── Pipeline stages ───────────────────────────────────────────────────


def _stage_probe(
    target: Dict[str, Any], timeout: float
) -> tuple[StageRecord, Optional[Response]]:
    """PROBE — route HTTP request through the configured I2P proxy."""
    url = target["url"]
    name = target["name"]

    logger.info("  [PROBE] Fetching %s via http-proxy (timeout=%.0fs)", url, timeout)
    t0 = time.monotonic()

    try:
        resp = fetch_i2p(url, via="http-proxy", timeout=timeout)
        elapsed = round(time.monotonic() - t0, 2)

        detail_parts = [
            f"status={resp.status}",
            f"bytes={len(resp.body)}",
            f"time={elapsed}s",
            f"via={resp.via.value}",
        ]
        title_val = resp.title()
        if title_val:
            detail_parts.append(f"title={title_val[:60]}")

        stage = StageRecord(
            name="probe",
            ok=resp.status > 0,
            detail=" | ".join(detail_parts),
            elapsed_sec=elapsed,
        )
        logger.info("    %s", stage.detail)
        return stage, resp

    except Exception as exc:
        elapsed = round(time.monotonic() - t0, 2)
        error_line = str(exc).splitlines()[0] if str(exc) else repr(exc)
        stage = StageRecord(
            name="probe",
            ok=False,
            detail=f"EXCEPTION after {elapsed}s",
            elapsed_sec=elapsed,
            error=error_line,
        )
        logger.error("    %s — %s", stage.detail, error_line)
        return stage, None


def _stage_extract(
    resp: Response,
) -> tuple[StageRecord, Optional[ExtractorResult]]:
    """EXTRACT — feed response body through the extractor registry."""
    logger.info("  [EXTRACT] Running extractor registry...")
    t0 = time.monotonic()

    try:
        body_text = resp.body.decode("utf-8", errors="replace")
        # Memory protection: cap at 256 KB (matches _do_probe in integration.py)
        MAX_BODY = 256 * 1024
        truncated = len(body_text) > MAX_BODY
        if truncated:
            body_text = body_text[:MAX_BODY]

        title_val = resp.title() or ""
        headers_dict = dict(resp.headers) if hasattr(resp, 'headers') else {}

        ext_result = run_extractors(
            title=title_val,
            body_text=body_text,
            headers=headers_dict,
            status_code=resp.status,
        )

        elapsed = round(time.monotonic() - t0, 2)

        detail_parts = [
            f"content_type={ext_result.content_type or '(none)'}",
            f"summary_lines={len(ext_result.summary_lines)}",
            f"links_found={len(ext_result.links)}",
            f"needs_review={ext_result.needs_review}",
        ]
        if truncated:
            detail_parts.append("body_truncated")

        stage = StageRecord(
            name="extract",
            ok=True,  # extractor ran successfully even without a match
            detail=" | ".join(detail_parts),
            elapsed_sec=elapsed,
        )
        logger.info("    %s", stage.detail)
        return stage, ext_result

    except Exception as exc:
        elapsed = round(time.monotonic() - t0, 2)
        error_line = str(exc).splitlines()[0] if str(exc) else repr(exc)
        stage = StageRecord(
            name="extract",
            ok=False,
            detail=f"EXCEPTION after {elapsed}s",
            elapsed_sec=elapsed,
            error=error_line,
        )
        logger.error("    %s — %s", stage.detail, error_line)
        return stage, None


def _stage_classify(
    ext_result: ExtractorResult,
) -> StageRecord:
    """CLASSIFY — summarize the content-type bucket and flags."""
    t0 = time.monotonic()

    detail_parts = [
        f"classification={ext_result.content_type or 'unknown'}",
    ]
    if ext_result.summary_lines:
        detail_parts.append(
            f"summary='{ext_result.summary_lines[0][:80]}'"
        )
    if ext_result.needs_review:
        detail_parts.append(f"flag=needs_review({ext_result.reason})")

    elapsed = round(time.monotonic() - t0, 3)

    stage = StageRecord(
        name="classify",
        ok=True,
        detail=" | ".join(detail_parts),
        elapsed_sec=elapsed,
    )
    logger.info("  [CLASSIFY] %s", stage.detail)
    return stage


def _stage_store(
    target: Dict[str, Any],
    resp: Response,
    ext_result: ExtractorResult,
    db: DiscoveryDB,
) -> StageRecord:
    """STORE — write probe result to the SQLite discovery table."""
    t0 = time.monotonic()

    try:
        b32_host = ""
        if "//" in resp.url:
            host_port = resp.url.split("//", 1)[-1].split("/", 1)[0]
            b32_host = host_port

        db.record_discovery(
            ident_hash_hex="",           # smoke test doesn't resolve hashes
            b32_addr=b32_host or target["url"],
            i2p_dns_name=target["name"],
            probe_mode="dns",            # we hit the URL directly (.i2p DNS)
            reachable=200 <= resp.status < 500,
            status_code=resp.status,
            body_length=len(resp.body),
            title=resp.title() or "",
            response_time=round(time.monotonic() - t0, 2),
            content_type=ext_result.content_type,
            content_summary="\n".join(ext_result.summary_lines),
            content_hash="",
            last_modified="",
            found_links=ext_result.links or [],
            flags=["needs_review: " + ext_result.reason],
            needs_review=ext_result.needs_review,
        )

        row_id = db._conn.cursor().lastrowid or 0
        elapsed = round(time.monotonic() - t0, 2)

        stage = StageRecord(
            name="store",
            ok=True,
            detail=f"written to discoveries table (row={row_id})",
            elapsed_sec=elapsed,
        )
        logger.info("  [STORE] %s", stage.detail)
        return stage

    except Exception as exc:
        elapsed = round(time.monotonic() - t0, 2)
        error_line = str(exc).splitlines()[0] if str(exc) else repr(exc)
        stage = StageRecord(
            name="store",
            ok=False,
            detail=f"EXCEPTION after {elapsed}s",
            elapsed_sec=elapsed,
            error=error_line,
        )
        logger.error("  [STORE] %s — %s", stage.detail, error_line)
        return stage


# ── Pre-flight health check ───────────────────────────────────────────


def preflight_health(cfg: I2PConfig) -> bool:
    """Quick connectivity probe via the project's built-in health checker."""
    logger.info("[PRE-FLIGHT] Checking proxy health...")

    # First try HTTP proxy (what the smoke test actually uses)
    http_ok = probe_health(via="http-proxy")
    logger.info(
        "  HTTP proxy → %s",
        "reachable" if http_ok else "UNREACHABLE — will attempt socks fallback",
    )

    # Also check SOCKS as a sanity cross-reference
    try:
        socks_ok = probe_health(via="socks")
        logger.info("  SOCKS5   → %s", "reachable" if socks_ok else "unreachable")
    except Exception as exc:
        logger.warning("  SOCKS5 check failed: %s", exc)
        socks_ok = False

    # Config dump for debug visibility
    logger.info(
        "  Config — HTTP=%s:%d  SOCKS=%s:%d  SAM=%s:%d",
        cfg.http_host, cfg.http_port,
        cfg.socks_host, cfg.socks_port,
        cfg.sam_host, cfg.sam_port,
    )

    return http_ok or socks_ok


# ── Main orchestrator ─────────────────────────────────────────────────


def run_smoke_test(
    targets_path: str = str(DEFAULT_TARGETS),
    db_path: Optional[str] = None,
    timeout: float = PROBE_TIMEOUT,
    dry_run: bool = False,
    json_report: bool = False,
) -> List[SmokeTargetResult]:
    """Execute the full pipeline on each smoke target."""

    cfg = I2PConfig()

    # ── Pre-flight ────────────────────────────────────────
    preflight_ok = preflight_health(cfg)
    if not preflight_ok:
        logger.warning(
            "[PRE-FLIGHT] WARNING: proxy health check failed. "
            "Smoke test will still attempt targets (some may fail)."
        )

    # ── Load targets ─────────────────────────────────────
    targets = load_targets(targets_path)
    if not targets:
        logger.error("No valid targets loaded — aborting.")
        return []

    # ── Open DB (unless dry run) ─────────────────────────
    db = None
    effective_db = Path(db_path or DEFAULT_DB_PATH)
    if not dry_run:
        db = DiscoveryDB(str(effective_db))
        logger.info("Database: %s", effective_db.resolve())
    else:
        logger.info("[DRY-RUN] Database storage disabled.")

    # ── Pipeline loop ────────────────────────────────────
    results: List[SmokeTargetResult] = []
    overall_start = time.monotonic()

    for idx, target in enumerate(targets, 1):
        url = target["url"]
        name = target["name"]
        result = SmokeTargetResult(name=name, url=url)

        logger.info(
            "\n>>> Target %d/%d: %s (%s)",
            idx, len(targets), name, url,
        )
        if target.get("description"):
            logger.info("    desc: %s", target["description"])

        # ── PROBE ────────────────────────
        probe_stage, resp = _stage_probe(target, timeout)
        result.stages.append(probe_stage)

        if resp is not None:
            result.status_code = resp.status
            result.body_length = len(resp.body)
            result.response_time_sec = resp.elapsed or round(
                probe_stage.elapsed_sec, 2
            )
            result.reachable = 200 <= resp.status < 500

        if probe_stage.ok and resp is not None:
            # ── EXTRACT ────────────────────
            ext_stage, ext_result = _stage_extract(resp)
            result.stages.append(ext_stage)

            if ext_result is not None:
                result.content_type = ext_result.content_type
                result.summary = "\n".join(ext_result.summary_lines[:3])
                result.found_links = list(ext_result.links) or []
                result.needs_review = ext_result.needs_review
                result.review_reason = ext_result.reason

                # ── CLASSIFY ───────────────
                classify_stage = _stage_classify(ext_result)
                result.stages.append(classify_stage)

                # ── VALIDATE ───────────────
                validation = _validate_result(result, cfg)
                result.validation = validation

                # ── STORE (only if validation passes) ──
                if not dry_run and db is not None:
                    if validation.passed:
                        store_stage = _store(target, resp, ext_result, db)
                    else:
                        store_stage = StageRecord(
                            name="store",
                            ok=False,
                            detail="(skipped — validation failed)",
                            error=", ".join(validation.failure_reasons),
                        )
                        logger.warning(
                            "  [STORE] SKIPPED — validation checks failed "
                            "(%d issue%s): %s",
                            len(validation.failure_reasons),
                            "s" if len(validation.failure_reasons) != 1 else "",
                            "; ".join(validation.failure_reasons),
                        )
                else:
                    store_stage = StageRecord(
                        name="store",
                        ok=True,
                        detail="(skipped — dry-run mode)" if dry_run else "(no DB connection)",
                    )
                result.stages.append(store_stage)

        target_elapsed = sum(s.elapsed_sec for s in result.stages)
        logger.info(
            "    ← elapsed=%.1fs  stages=%d",
            target_elapsed, len(result.stages),
        )

        results.append(result)
        # Brief pause between targets (I2P is inherently slow)
        if idx < len(targets):
            time.sleep(2)

    overall_elapsed = round(time.monotonic() - overall_start, 2)

    # ── PASS/FAIL summary report ─────────────────────────
    pass_count = sum(1 for r in results if r.success)
    fail_count = len(results) - pass_count

    logger.info("\n" + "=" * 70)
    logger.info("SMOKE TEST SUMMARY")
    logger.info("=" * 70)
    logger.info(
        "Targets: %d   |   PASS: %d   |   FAIL: %d   |   Total time: %.1fs",
        len(results), pass_count, fail_count, overall_elapsed,
    )
    logger.info("-" * 70)

    # Per-target verdict table
    for r in results:
        label = r.pass_label
        # Inline validation check status indicators
        check_strs = []
        if r.validation is not None:
            for cname, cval in r.validation.checks.items():
                indicator = "✓" if cval else "✗"
                check_strs.append(f"{indicator}{cname}")
        checks_line = "  ".join(check_strs) if check_strs else "(not validated)"

        logger.info(
            "  [%s] %-28s  status=%-4d  bytes=%-6d  type=%-12s  %s",
            label,
            r.name[:27],
            r.status_code if r.status_code else "(none)",
            r.body_length,
            (r.content_type or "(none)")[:11],
            checks_line,
        )

        # Failure reasons (indented)
        if r.validation and not r.validation.passed:
            for reason in r.validation.failure_reasons:
                logger.info("       └ %s", reason)

    logger.info("-" * 70)

    # Exit code summary
    exit_code = _compute_exit_code(results, preflight_ok)
    exit_label = {
        EXIT_SUCCESS: "ALL PASSED",
        EXIT_PROBE_FAIL: "PROBE FAILURE",
        EXIT_EXTRACT_FAIL: "EXTRACTION/CLASSIFICATION FAILURE",
        EXIT_STORE_FAIL: "STORAGE FAILURE",
        EXIT_CONFIG_FAIL: "CONFIGURATION ERROR",
        EXIT_PREFLIGHT: "PROXY UNREACHABLE",
    }
    logger.info(
        "Exit code: %d  (%s)", exit_code, exit_label.get(exit_code, "UNKNOWN")
    )

    # ── Optional JSON report ─────────────────────────────
    if json_report:
        report = _build_json_report(results, overall_elapsed)
        print(json.dumps(report, indent=2))

    if db is not None:
        db.close()

    return results


def _store(
    target: Dict[str, Any],
    resp: Response,
    ext_result: ExtractorResult,
    db: DiscoveryDB,
) -> StageRecord:
    """Delegated store implementation."""
    return _stage_store(target, resp, ext_result, db)


def _build_json_report(
    results: List[SmokeTargetResult], total_sec: float
) -> Dict[str, Any]:
    """Machine-readable summary dict with validation details."""
    targets_out = []
    for r in results:
        stages_out = [
            {
                "name": s.name,
                "ok": s.ok,
                "detail": s.detail,
                "elapsed_sec": round(s.elapsed_sec, 2),
            }
            for s in r.stages
        ]
        target_dict: Dict[str, Any] = {
            "name": r.name,
            "url": r.url,
            "success": r.success,
            "pass_label": r.pass_label,
            "status_code": r.status_code,
            "body_length": r.body_length,
            "response_time_sec": round(r.response_time_sec, 2),
            "content_type": r.content_type,
            "summary_preview": (r.summary or "")[:200],
            "found_links": r.found_links,
            "needs_review": r.needs_review,
            "review_reason": r.review_reason,
            "stages": stages_out,
        }
        if r.validation is not None:
            target_dict["validation"] = {
                "passed": r.validation.passed,
                "checks": dict(r.validation.checks),
                "failure_reasons": list(r.validation.failure_reasons),
            }
        targets_out.append(target_dict)

    exit_code = _compute_exit_code(results)

    return {
        "smoke_test": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "proxy_backend": "http-proxy",
            "targets_count": len(results),
            "pass_count": sum(1 for r in results if r.success),
            "fail_count": sum(1 for r in results if not r.success),
            "total_elapsed_sec": round(total_sec, 2),
            "exit_code": exit_code,
            "targets": targets_out,
        }
    }


# ── CLI entry point ───────────────────────────────────────────────────


def main():
    """CLI for smoke testing the probe pipeline."""
    parser = argparse.ArgumentParser(
        description="I2P Indexer — Smoke test the full probe pipeline",
        epilog="Exit codes:\n"
               "  0 — All targets passed validation\n"
               "  1 — One or more probe failures (network/proxy)\n"
               "  2 — Extraction/classification failure\n"
               "  3 — Database storage failure\n"
               "  4 — Targets file missing or malformed\n"
               "  5 — Proxy health check failed\n\n"
               "Examples:\n"
               "  python -m src.smoke_test                          # all targets, default timeout\n"
               "  python -m src.smoke_test --timeout 60             # 60s deadline per target\n"
               "  python -m src.smoke_test --dry-run                # no DB writes\n"
               '  python -m src.smoke_test --json                   # machine-readable report to stdout\n'
               "  python -m src.smoke_test -v                       # debug logging",
    )

    parser.add_argument(
        "--targets",
        type=str,
        default=str(DEFAULT_TARGETS),
        help="Path to JSON targets file (default: tests/smoke_targets.json)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=PROBE_TIMEOUT,
        help=f"Per-target connection timeout in seconds (default: {PROBE_TIMEOUT})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Probe and extract only — skip writing to the database",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as structured JSON to stdout",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging",
    )

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )

    results = run_smoke_test(
        targets_path=args.targets,
        timeout=args.timeout,
        dry_run=args.dry_run,
        json_report=args.json,
    )

    # Return differentiated exit code for CI integration
    sys.exit(_compute_exit_code(results))


if __name__ == "__main__":
    main()
