#!/usr/bin/env python3
"""Live smoke test for I2P probe + extract pipeline.

Tests against historically reachable .i2p sites to verify the full pipeline:
1. Proxy connectivity (fetch_i2p through HTTP proxy)
2. Successful probe (HTTP 200 with content)
3. Extractor classification (content_type assigned, needs_review handled)

Targets are in smoke_targets.json and should be refreshed monthly.
Run with: python -m pytest tests/smoke_test.py -v --tb=short

Note: These tests make real network calls through the I2P proxy. They may
fail due to network conditions (netDB sparsity, target downtime) which is
NOT a test failure but a network condition. The important thing is that
reachable sites produce properly classified results without crashes.
"""

import json
import os
import sys
import unittest
from pathlib import Path

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.i2p_proxy import fetch_i2p
from src.extractors import run_extractors


def load_smoke_targets():
    """Load smoke targets from JSON config."""
    target_file = Path(__file__).parent / "smoke_targets.json"
    with open(target_file) as f:
        data = json.load(f)
    return data["targets"]


class TestSmokeProbe(unittest.TestCase):
    """Live I2P probe tests. Skip if proxy unreachable."""

    targets = []
    _loaded = False

    @classmethod
    def setUpClass(cls):
        if cls._loaded:
            return
        try:
            cls.targets = load_smoke_targets()
            cls._loaded = True
        except FileNotFoundError:
            raise unittest.SkipTest("smoke_targets.json not found")

    def _probe_and_extract(self, target):
        """Probe a single target and run extractors. Returns dict with results."""
        url = target["url"]
        result = {
            "name": target["name"],
            "url": url,
            "probed": False,
            "status": None,
            "content_bytes": 0,
            "extracted": False,
            "content_type": None,
            "needs_review": None,
            "error": None,
        }

        try:
            resp = fetch_i2p(url, timeout=60)
            result["probed"] = True
            result["status"] = resp.status
            result["content_bytes"] = len(resp.body) if resp.body else 0

            if resp.ok:
                # Safely get title - handle both string and callable cases
                title_val = resp.title
                if callable(title_val):
                    title_val = title_val()
                if not isinstance(title_val, str):
                    title_val = str(title_val) if title_val else ""

                # Run extractors
                body_text = resp.text if resp.text else ""
                extractor_result = run_extractors(
                    title=title_val,
                    body_text=body_text,
                    headers=dict(resp.headers) if resp.headers else None,
                    status_code=resp.status,
                )

                result["extracted"] = bool(extractor_result.content_type)
                result["content_type"] = extractor_result.content_type
                result["needs_review"] = extractor_result.needs_review

        except Exception as e:
            result["error"] = str(e)[:120]

        return result

    def test_at_least_one_target_reachable(self):
        """Verify at least one target responds (network connectivity check)."""
        results = []
        for target in self.targets:
            r = self._probe_and_extract(target)
            results.append(r)

        reachable = [r for r in results if r["probed"] and r["status"] == 200]
        print(f"\nSmoke test results:")
        for r in results:
            status_icon = "✓" if r["probed"] and r["status"] == 200 else "✗"
            print(f"  {status_icon} {r['name']}: status={r['status']}, "
                  f"bytes={r['content_bytes']}, extracted={r['extracted']}")

        # We don't require all targets to be up (I2P availability varies),
        # but we need at least 1 to verify the pipeline works
        self.assertGreaterEqual(
            len(reachable),
            1,
            f"No targets reachable. Network condition or proxy issue. "
            f"Results: {[r['name'] for r in results]}",
        )

    def test_successful_probe_produces_extraction(self):
        """When a site is reachable, extractors must not crash and must produce results."""
        for target in self.targets:
            r = self._probe_and_extract(target)
            if r["probed"] and r["status"] == 200:
                # Extractors should either classify or flag needs_review
                # They should NEVER crash
                self.assertIsNone(
                    r["error"],
                    f"{target['name']}: extractor crashed: {r['error']}",
                )
                # At minimum, we should have a content_type OR needs_review=True
                has_classification = r["content_type"] is not None or r["needs_review"] is True
                self.assertTrue(
                    has_classification,
                    f"{target['name']}: no classification and no needs_review flag",
                )


class TestSmokePipelineIntegration(unittest.TestCase):
    """Test the full pipeline with known-good target."""

    def test_extractors_handle_empty_title(self):
        """Extractors should handle empty/None titles gracefully."""
        result = run_extractors(
            title="",
            body_text="<html><body><h1>Test</h1><p>Content</p></body></html>",
            headers={"Content-Type": "text/html"},
            status_code=200,
        )
        self.assertIsNotNone(result)

    def test_extractors_handle_none_body(self):
        """Extractors should handle empty body."""
        result = run_extractors(
            title="Test Title",
            body_text="",
            headers=None,
            status_code=200,
        )
        self.assertIsNotNone(result)

    def test_extractors_dont_crash_on_html(self):
        """Basic HTML should be handled without crashing (may not classify)."""
        html = "<html><head><title>Test Site</title></head>" \
               "<body><p>This is a test page.</p></body></html>"
        result = run_extractors(
            title="Test Site",
            body_text=html,
            headers={"Content-Type": "text/html"},
            status_code=200,
        )
        # Should not crash; may or may not classify minimal HTML
        self.assertIsNotNone(result)
        # Either classified or has summary (not a hard failure either way)
        self.assertTrue(
            result.content_type != "" or len(result.summary_lines) > 0,
            "Extractors produced no output at all",
        )


if __name__ == "__main__":
    unittest.main()
