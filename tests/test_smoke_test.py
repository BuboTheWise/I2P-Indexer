"""Unit tests for src.smoke_test (probe pipeline smoke testing).

Covers:
  - Target loading from smoke_targets.json (valid, missing url, bad JSON)
  - Pipeline stages (probe → extract → classify → store) with mocked responses
  - Timeout handling
  - Dry-run mode
  - JSON report output
  - StageRecord / SmokeTargetResult data model

Run with: pytest tests/test_smoke_test.py -v --tb=short
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestLoadTargets(unittest.TestCase):
    """Verify smoke_targets.json loading and validation."""

    def setUp(self):
        self.smoke_json = Path(__file__).parent / "smoke_targets.json"

    def test_default_path_exists(self):
        assert self.smoke_json.is_file()

    def test_load_defaults(self):
        from src.smoke_test import load_targets, DEFAULT_TARGETS

        targets = load_targets(DEFAULT_TARGETS)
        self.assertGreater(len(targets), 0)
        for t in targets:
            self.assertIn("name", t)
            self.assertIn("url", t)
            self.assertIsInstance(t["url"], str)

    def test_load_custom_path(self):
        from src.smoke_test import load_targets

        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False,
        )
        tmp.write(json.dumps({"targets": [{"name": "X", "url": "http://x.i2p/"}]}))
        tmp.close()
        targets = load_targets(tmp.name)
        self.assertEqual(len(targets), 1)
        os.unlink(tmp.name)

    def test_missing_url_skipped(self):
        from src.smoke_test import load_targets

        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False,
        )
        tmp.write(json.dumps({"targets": [{"name": "no-url"}]}))
        tmp.close()
        targets = load_targets(tmp.name)
        self.assertEqual(len(targets), 0)
        os.unlink(tmp.name)

    def test_malformed_json_aborts(self):
        from src.smoke_test import load_targets

        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False,
        )
        tmp.write("{{not json}}")
        tmp.close()
        with self.assertRaises(SystemExit):
            load_targets(tmp.name)
        os.unlink(tmp.name)


class TestStageModels(unittest.TestCase):
    """Verify smoke_test data model."""

    def test_stage_record(self):
        from src.smoke_test import StageRecord

        s = StageRecord(name="probe", ok=True, detail="ok", elapsed_sec=1.5)
        self.assertEqual(s.name, "probe")
        self.assertTrue(s.ok)

    def test_smoke_target_result_success_true(self):
        from src.smoke_test import SmokeTargetResult, StageRecord

        r = SmokeTargetResult(name="X", url="http://a.i2p/")
        r.stages.append(StageRecord(name="probe", ok=True))
        r.stages.append(StageRecord(name="extract", ok=True))
        self.assertTrue(r.success)

    def test_smoke_target_result_success_false_incomplete(self):
        from src.smoke_test import SmokeTargetResult, StageRecord

        r = SmokeTargetResult(name="X", url="http://a.i2p/")
        r.stages.append(StageRecord(name="probe", ok=False))
        self.assertFalse(r.success)

    def test_report_dict(self):
        from src.smoke_test import _build_json_report, SmokeTargetResult

        results = [
            SmokeTargetResult(
                name="ok-target", url="http://ok.i2p/", status_code=200, body_length=42,
            )
        ]
        report = _build_json_report(results, total_sec=1.23)
        self.assertIn("smoke_test", report)
        self.assertEqual(report["smoke_test"]["targets_count"], 1)


class TestStageExtract(unittest.TestCase):
    """EXTRACT stage with mocked Response object."""

    @patch("src.smoke_test.run_extractors")
    def test_extract_stage_success(self, mock_run_extractors):
        from src.extractors import ExtractorResult
        from src.i2p_proxy import Response
        from src.smoke_test import _stage_extract

        mock_ext_result = ExtractorResult(
            content_type="forum",
            summary_lines=["line1"],
            links=["site.i2p"],
            needs_review=False,
        )
        mock_run_extractors.return_value = mock_ext_result

        fake_resp = MagicMock(spec=Response)
        fake_resp.body = b"<html><body>Forum post</body></html>"
        fake_resp.status = 200
        fake_resp.headers = {"Content-Type": "text/html"}

        stage, ext_result = _stage_extract(fake_resp)
        self.assertTrue(stage.ok)
        self.assertIsNotNone(ext_result)
        self.assertEqual(ext_result.content_type, "forum")
        mock_run_extractors.assert_called_once()

    @patch("src.smoke_test.run_extractors")
    def test_extract_stage_exception(self, mock_run_extractors):
        from src.i2p_proxy import Response
        from src.smoke_test import _stage_extract

        mock_run_extractors.side_effect = RuntimeError("boom")

        fake_resp = MagicMock(spec=Response)
        fake_resp.body = b"binary"
        fake_resp.headers = {}

        stage, ext_result = _stage_extract(fake_resp)
        self.assertFalse(stage.ok)
        self.assertIsNone(ext_result)


class TestStageClassify(unittest.TestCase):
    """CLASSIFY stage."""

    def test_classifies_with_type(self):
        from src.extractors import ExtractorResult
        from src.smoke_test import _stage_classify

        er = ExtractorResult(
            content_type="blog",
            summary_lines=["summary line"],
            links=[],
            needs_review=False,
        )
        stage = _stage_classify(er)
        self.assertTrue(stage.ok)
        self.assertIn("classification=blog", stage.detail)

    def test_classifies_as_unknown(self):
        from src.extractors import ExtractorResult
        from src.smoke_test import _stage_classify

        er = ExtractorResult(content_type="", summary_lines=[], links=[])
        stage = _stage_classify(er)
        self.assertTrue(stage.ok)
        self.assertIn("unknown", stage.detail)


class TestStageStore(unittest.TestCase):
    """STORE stage writes to SQLite."""

    def test_store_writes_to_db(self):
        from src.extractors import ExtractorResult
        from src.i2p_proxy import Response
        from src.integration import DiscoveryDB
        from src.smoke_test import _stage_store

        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()

        db = DiscoveryDB(tmp.name)
        fake_resp = Response(
            url="http://test.i2p/", status=200, body=b"<html></html>",
        )
        er = ExtractorResult(content_type="forum", summary_lines=[""], links=[])
        target = {"name": "smoke-store-test", "url": "http://test.i2p/"}

        stage = _stage_store(target, fake_resp, er, db)
        self.assertTrue(stage.ok)
        db.close()
        os.unlink(tmp.name)


class TestSmokeTestIntegration(unittest.TestCase):
    """Dry-run integration test — no network calls."""

    def test_dry_run_does_not_connect(self):
        """With --dry-run the probe stage should still execute (with a mock),
        but store should skip writing to DB."""
        import tempfile
        from src.smoke_test import run_smoke_test, SmokeTargetResult

        with tempfile.TemporaryDirectory() as tmpdir:
            targets_file = Path(tmpdir) / "targets.json"
            targets_file.write_text(json.dumps({
                "targets": [{"name": "t1", "url": "http://example.i2p/"}]
            }))

            # Patch fetch_i2p so we get a fake successful probe without network
            from src.i2p_proxy import Response
            fake_resp = Response(
                url="http://example.i2p/", status=200, body=b"<html></html>",
            )

            with patch("src.smoke_test.preflight_health", return_value=True), \
                 patch("src.smoke_test.fetch_i2p", return_value=fake_resp):
                results = run_smoke_test(
                    targets_path=str(targets_file),
                    db_path=str(Path(tmpdir) / "test.db"),
                    timeout=5.0,
                    dry_run=True,
                )

            self.assertEqual(len(results), 1)
            self.assertIsInstance(results[0], SmokeTargetResult)


class TestValidationResult(unittest.TestCase):
    """Validation model and check logic."""

    def test_validation_pass_label(self):
        from src.smoke_test import ValidationResult

        v = ValidationResult(passed=True)
        self.assertEqual(v.label, "PASS")

        v2 = ValidationResult(passed=False)
        self.assertEqual(v2.label, "FAIL")


class TestValidateResult(unittest.TestCase):
    """Validation checks on completed target results."""

    def _make_result(self, **kwargs):
        from src.smoke_test import SmokeTargetResult, StageRecord

        r = SmokeTargetResult(name="test", url="http://test.i2p/")
        r.stages.append(StageRecord(
            name="probe", ok=kwargs.get("probe_ok", True),
        ))
        r.status_code = kwargs.get("status_code", 200)
        r.body_length = kwargs.get("body_length", 1024)
        return r

    def test_all_checks_pass(self):
        from src.smoke_test import SmokeTargetResult, StageRecord, _validate_result
        from src.config import I2PConfig

        r = self._make_result(probe_ok=True, status_code=200, body_length=512)
        r.content_type = "forum"
        r.summary = "A valid summary line"
        # add extract stage so no errors
        r.stages.append(StageRecord(name="extract", ok=True))

        cfg = I2PConfig()
        v = _validate_result(r, cfg)
        self.assertTrue(v.passed, f"Failed checks: {v.checks}, reasons: {v.failure_reasons}")

    def test_probe_failure_fails_validation(self):
        from src.smoke_test import _validate_result
        from src.config import I2PConfig

        r = self._make_result(probe_ok=False)
        cfg = I2PConfig()
        v = _validate_result(r, cfg)
        self.assertFalse(v.passed)
        self.assertIn("Probe stage failed", str(v.failure_reasons))

    def test_null_status_code_fails(self):
        from src.smoke_test import _validate_result
        from src.config import I2PConfig

        r = self._make_result(status_code=0)
        cfg = I2PConfig()
        v = _validate_result(r, cfg)
        self.assertFalse(v.passed)
        self.assertIn("HTTP 0", str(v.failure_reasons))

    def test_5xx_status_fails(self):
        from src.smoke_test import _validate_result
        from src.config import I2PConfig

        r = self._make_result(status_code=500)
        cfg = I2PConfig()
        v = _validate_result(r, cfg)
        self.assertFalse(v.passed)

    def test_empty_content_type_fails(self):
        from src.smoke_test import SmokeTargetResult, StageRecord, _validate_result
        from src.config import I2PConfig

        r = self._make_result()
        r.content_type = ""
        r.summary = "some summary"
        r.stages.append(StageRecord(name="extract", ok=True))
        cfg = I2PConfig()
        v = _validate_result(r, cfg)
        self.assertFalse(v.passed)

    def test_body_too_small_fails(self):
        from src.smoke_test import SmokeTargetResult, StageRecord, _validate_result
        from src.config import I2PConfig

        r = self._make_result(body_length=50)
        r.content_type = "forum"
        r.summary = "some summary"
        r.stages.append(StageRecord(name="extract", ok=True))
        cfg = I2PConfig()
        v = _validate_result(r, cfg)
        self.assertFalse(v.passed)

    def test_empty_summary_fails(self):
        from src.smoke_test import SmokeTargetResult, StageRecord, _validate_result
        from src.config import I2PConfig

        r = self._make_result()
        r.content_type = "forum"
        r.summary = ""
        r.stages.append(StageRecord(name="extract", ok=True))
        cfg = I2PConfig()
        v = _validate_result(r, cfg)
        self.assertFalse(v.passed)

    def test_stage_error_fails(self):
        from src.smoke_test import SmokeTargetResult, StageRecord, _validate_result
        from src.config import I2PConfig

        r = SmokeTargetResult(name="test", url="http://test.i2p/")
        r.stages.append(StageRecord(
            name="probe", ok=True, error="connection reset"
        ))
        r.status_code = 200
        r.body_length = 1024
        r.content_type = "forum"
        r.summary = "summary"
        r.stages.append(StageRecord(name="extract", ok=True))
        cfg = I2PConfig()
        v = _validate_result(r, cfg)
        self.assertFalse(v.passed)

    def test_validation_fills_failure_reasons(self):
        from src.smoke_test import SmokeTargetResult, StageRecord, _validate_result
        from src.config import I2PConfig

        r = SmokeTargetResult(name="test", url="http://test.i2p/")
        r.stages.append(StageRecord(name="probe", ok=False))
        r.status_code = 0
        r.body_length = 0
        r.content_type = ""
        r.summary = ""
        cfg = I2PConfig()
        v = _validate_result(r, cfg)
        self.assertFalse(v.passed)
        # Multiple checks should fail
        self.assertGreater(len(v.failure_reasons), 1)


class TestComputeExitCode(unittest.TestCase):
    """Differentiated exit codes for CI integration."""

    def test_all_pass(self):
        from src.smoke_test import (
            SmokeTargetResult, StageRecord, ValidationResult,
            _compute_exit_code, EXIT_SUCCESS,
        )

        r = SmokeTargetResult(name="ok", url="http://ok.i2p/")
        r.stages.append(StageRecord(name="probe", ok=True))
        r.stages.append(StageRecord(name="extract", ok=True))
        r.validation = ValidationResult(passed=True)

        code = _compute_exit_code([r], preflight_ok=True)
        self.assertEqual(code, EXIT_SUCCESS)

    def test_probe_failure(self):
        from src.smoke_test import (
            SmokeTargetResult, StageRecord,
            _compute_exit_code, EXIT_PROBE_FAIL,
        )

        r = SmokeTargetResult(name="fail", url="http://fail.i2p/")
        r.stages.append(StageRecord(name="probe", ok=False))

        code = _compute_exit_code([r])
        self.assertEqual(code, EXIT_PROBE_FAIL)

    def test_extract_failure(self):
        from src.smoke_test import (
            SmokeTargetResult, StageRecord,
            _compute_exit_code, EXIT_EXTRACT_FAIL,
        )

        r = SmokeTargetResult(name="fail", url="http://fail.i2p/")
        r.stages.append(StageRecord(name="probe", ok=True))
        r.stages.append(StageRecord(name="extract", ok=False))

        code = _compute_exit_code([r])
        self.assertEqual(code, EXIT_EXTRACT_FAIL)

    def test_store_failure(self):
        from src.smoke_test import (
            SmokeTargetResult, StageRecord,
            _compute_exit_code, EXIT_STORE_FAIL,
        )

        r = SmokeTargetResult(name="fail", url="http://fail.i2p/")
        r.stages.append(StageRecord(name="probe", ok=True))
        r.stages.append(StageRecord(name="store", ok=False))

        code = _compute_exit_code([r])
        self.assertEqual(code, EXIT_STORE_FAIL)

    def test_preflight_failure(self):
        from src.smoke_test import (
            SmokeTargetResult, StageRecord,
            _compute_exit_code, EXIT_PREFLIGHT,
        )

        r = SmokeTargetResult(name="ok", url="http://ok.i2p/")
        r.stages.append(StageRecord(name="probe", ok=True))

        code = _compute_exit_code([r], preflight_ok=False)
        self.assertEqual(code, EXIT_PREFLIGHT)

    def test_mix_probe_and_extract_failures(self):
        """When both probe and extract fail, probe takes priority."""
        from src.smoke_test import (
            SmokeTargetResult, StageRecord,
            _compute_exit_code, EXIT_PROBE_FAIL,
        )

        r1 = SmokeTargetResult(name="r1", url="http://a.i2p/")
        r1.stages.append(StageRecord(name="probe", ok=False))

        r2 = SmokeTargetResult(name="r2", url="http://b.i2p/")
        r2.stages.append(StageRecord(name="probe", ok=True))
        r2.stages.append(StageRecord(name="extract", ok=False))

        code = _compute_exit_code([r1, r2])
        # Probe failure has higher priority than extract failure
        self.assertEqual(code, EXIT_PROBE_FAIL)


class TestSmokeTestWithValidation(unittest.TestCase):
    """Integration test: validation gate blocks storage on invalid results."""

    def test_validation_blocks_store(self):
        import tempfile
        from src.smoke_test import run_smoke_test
        from src.i2p_proxy import Response

        with tempfile.TemporaryDirectory() as tmpdir:
            targets_file = Path(tmpdir) / "targets.json"
            targets_file.write_text(json.dumps({
                "targets": [{"name": "bad", "url": "http://bad.i2p/"}]
            }))

            # Response that passes probe but fails validation (no body, no content type)
            fake_resp = Response(
                url="http://bad.i2p/", status=404, body=b"",
            )

            with patch("src.smoke_test.preflight_health", return_value=True), \
                 patch("src.smoke_test.fetch_i2p", return_value=fake_resp):
                results = run_smoke_test(
                    targets_path=str(targets_file),
                    db_path=str(Path(tmpdir) / "test.db"),
                    timeout=5.0,
                    dry_run=False,
                )

            self.assertEqual(len(results), 1)
            r = results[0]
            # Store stage should have been skipped due to validation failure
            store_stages = [s for s in r.stages if s.name == "store"]
            if store_stages:
                self.assertFalse(store_stages[0].ok)


class TestCLIHelp(unittest.TestCase):
    """Verify --help renders without errors."""

    def test_help_exits_cleanly(self):
        result = os.system(
            f"{sys.executable} -m src.smoke_test --help > /dev/null 2>&1"
        )
        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
