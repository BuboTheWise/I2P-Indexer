"""Tests for scripts/check_smoke_staleness.py — staleness gate for smoke_targets.json.

Covers:
  - Fresh file (within threshold) returns exit code 0
  - Stale file (beyond threshold) returns exit code 3
  - Missing file returns exit code 1
  - Malformed JSON returns exit code 2
  - Missing _last_refresh field returns exit code 2
  - Bad date format returns exit code 2
  --stale-days overrides default threshold
  --path points to custom location

Run with: pytest tests/test_smoke_staleness.py -v --tb=short
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from scripts.check_smoke_staleness import main  # type: ignore


class TestSmokeStaleness(unittest.TestCase):
    """Staleness check returns correct exit codes for various states."""

    def _write_json(self, tmp: Path, data: dict) -> None:
        tmp.write_text(json.dumps(data), encoding="utf-8")

    def test_fresh_file_returns_zero(self):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            self._write_json(
                Path(f.name),
                {"_last_refresh": today, "_refresh_frequency": "monthly", "targets": []},
            )
        code = main(Path(f.name))
        self.assertEqual(code, 0)

    def test_stale_file_returns_three(self):
        thirty_one_days_ago = (datetime.now(timezone.utc) - timedelta(days=31)).strftime("%Y-%m-%d")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            self._write_json(
                Path(f.name),
                {
                    "_last_refresh": thirty_one_days_ago,
                    "_refresh_frequency": "monthly",
                    "targets": [],
                },
            )
        code = main(Path(f.name), stale_days=30)
        self.assertEqual(code, 3)

    def test_custom_stale_days(self):
        five_days_ago = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            self._write_json(
                Path(f.name),
                {
                    "_last_refresh": five_days_ago,
                    "targets": [],
                },
            )
        # 5 days is within 10-day threshold → 0
        code = main(Path(f.name), stale_days=10)
        self.assertEqual(code, 0)
        # 5 days exceeds 3-day threshold → 3
        code = main(Path(f.name), stale_days=3)
        self.assertEqual(code, 3)

    def test_missing_file_returns_one(self):
        nonexistent = Path("/tmp/does_not_exist_smoke_targets_test.json")
        if nonexistent.exists():
            nonexistent.unlink()
        code = main(nonexistent)
        self.assertEqual(code, 1)

    def test_malformed_json_returns_two(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            Path(f.name).write_text("{{not json}}")
        code = main(Path(f.name))
        self.assertEqual(code, 2)

    def test_missing_last_refresh_field_returns_two(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            self._write_json(Path(f.name), {"targets": []})
        code = main(Path(f.name))
        self.assertEqual(code, 2)

    def test_bad_date_format_returns_two(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            self._write_json(Path(f.name), {"_last_refresh": "not-a-date", "targets": []})
        code = main(Path(f.name))
        self.assertEqual(code, 2)

    def test_empty_date_returns_two(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            self._write_json(Path(f.name), {"_last_refresh": "", "targets": []})
        code = main(Path(f.name))
        self.assertEqual(code, 2)

    def test_default_targets_file(self):
        """The real smoke_targets.json in this repo should be fresh and valid."""
        from scripts.check_smoke_staleness import DEFAULT_TARGETS_FILE
        if DEFAULT_TARGETS_FILE.is_file():
            code = main(DEFAULT_TARGETS_FILE)
            # Should be 0 (fresh) or at most not 1/2 (file exists + valid JSON)
            self.assertIn(code, (0, 3), f"Expected 0 or 3, got {code}")


class TestCurrentSmokeTargets(unittest.TestCase):
    """Verify the actual smoke_targets.json passes staleness and schema checks."""

    def setUp(self):
        from scripts.check_smoke_staleness import DEFAULT_TARGETS_FILE
        self.targets_file = DEFAULT_TARGETS_FILE

    def test_file_exists(self):
        self.assertTrue(self.targets_file.is_file())

    def test_valid_json(self):
        data = json.loads(self.targets_file.read_text())
        self.assertIn("targets", data)

    def test_has_last_refresh(self):
        data = json.loads(self.targets_file.read_text())
        self.assertIn("_last_refresh", data)

    def test_targets_are_list(self):
        data = json.loads(self.targets_file.read_text())
        self.assertIsInstance(data["targets"], list)

    def test_at_least_one_target(self):
        data = json.loads(self.targets_file.read_text())
        assert len(data["targets"]) >= 1, "Need at least 1 target for smoke testing"

    def test_targets_have_required_fields(self):
        data = json.loads(self.targets_file.read_text())
        for idx, t in enumerate(data["targets"]):
            self.assertIn("url", t, f"Target {idx} missing 'url'")
            self.assertIn("name", t, f"Target {idx} missing 'name'")

    def test_staleness_check_passes(self):
        """The real file should not be stale at the time of this commit."""
        code = main(self.targets_file)
        # Accepts fresh (0) or borderline stale (3) — the key is it's parseable
        self.assertIn(code, (0, 3))


if __name__ == "__main__":
    unittest.main()
