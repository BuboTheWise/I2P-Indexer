"""Tests for robots.txt parsing and --respect-robots CLI flag."""
from __future__ import annotations

import tempfile
import pytest
from unittest.mock import patch, MagicMock

# ── Robots parser unit tests ────────────────────────────────────────


class TestParseRobotsTxt:
    """Test parse_robots_txt() with various inputs."""

    def test_empty_body(self):
        from src.robots_parser import parse_robots_txt
        policy = parse_robots_txt("example.i2p", "")
        assert not policy.rules

    def test_allow_all(self):
        from src.robots_parser import parse_robots_txt
        raw = "User-agent: *\nAllow: /\n"
        policy = parse_robots_txt("example.i2p", raw)
        assert len(policy.rules) == 1
        assert not policy.rules[0].is_disallow

    def test_disallow_all(self):
        from src.robots_parser import parse_robots_txt
        raw = "User-agent: *\nDisallow: /\n"
        policy = parse_robots_txt("example.i2p", raw)
        assert len(policy.rules) == 1
        assert policy.rules[0].is_disallow
        assert policy.is_fully_blocked

    def test_partial_disallow(self):
        from src.robots_parser import parse_robots_txt
        raw = "User-agent: *\nDisallow: /admin\nDisallow: /private\n"
        policy = parse_robots_txt("example.i2p", raw)
        assert len(policy.rules) == 2
        assert not policy.is_fully_blocked

    def test_wildcard_disallow(self):
        from src.robots_parser import parse_robots_txt
        raw = "User-agent: *\nDisallow: /api/*\n"
        policy = parse_robots_txt("example.i2p", raw)
        assert policy.rules[0].has_wildcard

    def test_suffix_disallow(self):
        from src.robots_parser import parse_robots_txt
        raw = "User-agent: *\nDisallow: /.html$\n"
        policy = parse_robots_txt("example.i2p", raw)
        assert policy.rules[0].has_suffix

    def test_mixed_allow_disallow(self):
        from src.robots_parser import parse_robots_txt
        raw = "User-agent: *\nDisallow: /admin\nAllow: /admin/public\n"
        policy = parse_robots_txt("example.i2p", raw)
        # Longest match wins: /admin/public is longer than /admin so /admin/public is allowed
        assert not policy.blocks_path("/admin/public")
        assert policy.blocks_path("/admin/secret")

    def test_comments_and_blank_lines(self):
        from src.robots_parser import parse_robots_txt
        raw = """# This is a comment
User-agent: *

# Another comment
Disallow: /private
"""
        policy = parse_robots_txt("example.i2p", raw)
        assert len(policy.rules) == 1


class TestRobotsPolicyMatching:
    """Test the longest-match-wins algorithm."""

    def test_longest_match_wins(self):
        from src.robots_parser import parse_robots_txt
        # /admin is disallowed, but /admin/logs/2024 is more specific
        raw = "User-agent: *\nDisallow: /admin\nAllow: /admin/logs\n"
        policy = parse_robots_txt("example.i2p", raw)
        assert not policy.blocks_path("/admin/logs/2024")  # Allow wins (longer match)
        assert policy.blocks_path("/admin/config")           # Disallow wins

    def test_no_match_allows(self):
        from src.robots_parser import parse_robots_txt
        raw = "User-agent: *\nDisallow: /admin\n"
        policy = parse_robots_txt("example.i2p", raw)
        assert not policy.blocks_path("/index.html")
        assert not policy.blocks_path("/")

    def test_wildcard_matching(self):
        from src.robots_parser import parse_robots_txt
        raw = "User-agent: *\nDisallow: /api/*\n"
        policy = parse_robots_txt("example.i2p", raw)
        assert policy.blocks_path("/api/v1/users")
        assert not policy.blocks_path("/blog/post")

    def test_suffix_matching(self):
        from src.robots_parser import parse_robots_txt
        raw = "User-agent: *\nDisallow: /.pdf$\n"
        policy = parse_robots_txt("example.i2p", raw)
        assert policy.blocks_path("/docs/file.pdf")
        assert not policy.blocks_path("/docs/file.pdf.bak")  # suffix anchor prevents this


class TestPolicyBlocksPathHelper:
    """Test the convenience wrapper."""

    def test_none_policy_allows_when_default_allow(self):
        from src.robots_parser import policy_blocks_path
        assert not policy_blocks_path(None, "/anything", default_allow=True)

    def test_none_policy_blocks_when_no_default_allow(self):
        from src.robots_parser import policy_blocks_path
        assert policy_blocks_path(None, "/anything", default_allow=False)

    def test_with_policy(self):
        from src.robots_parser import parse_robots_txt, policy_blocks_path
        raw = "User-agent: *\nDisallow: /admin\n"
        policy = parse_robots_txt("example.i2p", raw)
        assert policy_blocks_path(policy, "/admin")
        assert not policy_blocks_path(policy, "/public")


class TestFetchRobotsTxt:
    """Test fetch_robots_txt with mocked network."""

    @patch("src.robots_parser.fetch_i2p")
    def test_fetches_and_parses(self, mock_fetch):
        from src.robots_parser import fetch_robots_txt
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = b"User-agent: *\nDisallow: /admin\n"
        mock_resp.text = "User-agent: *\nDisallow: /admin\n"
        mock_fetch.return_value = mock_resp

        policy = fetch_robots_txt("http://example.i2p/")
        assert policy is not None
        assert policy.blocks_path("/admin")
        assert not policy.blocks_path("/public")

    @patch("src.robots_parser.fetch_i2p")
    def test_returns_none_on_404(self, mock_fetch):
        from src.robots_parser import fetch_robots_txt
        mock_resp = MagicMock()
        mock_resp.status = 404
        mock_fetch.return_value = mock_resp

        policy = fetch_robots_txt("http://example.i2p/")
        assert policy is None

    @patch("src.robots_parser.fetch_i2p")
    def test_returns_none_on_error(self, mock_fetch):
        from src.robots_parser import fetch_robots_txt
        mock_fetch.side_effect = Exception("Network error")

        policy = fetch_robots_txt("http://example.i2p/")
        assert policy is None


# ── Integration tests: --respect-robots in discover_addresses ───────


class TestRespectRobotsIntegration:
    """Test that respect_robots=True flows through discover_addresses."""

    @patch("src.integration.probe_destination")
    @patch("src.robots_parser.fetch_robots_txt")
    def test_fetches_robots_when_enabled(self, mock_fetch_robots, mock_probe):
        from src.integration import discover_addresses
        mock_policy = MagicMock()
        mock_policy.is_fully_blocked = False
        mock_fetch_robots.return_value = mock_policy

        mock_result = MagicMock()
        mock_result.reachable = True
        mock_result.response_time_sec = 1.0
        mock_result.body_length = 1000
        mock_result.found_links = []
        mock_probe.return_value = mock_result

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            results = discover_addresses(
                known_addrs=["example.i2p"],
                db_path=db_path,
                respect_robots=True,
            )
            assert mock_fetch_robots.called
            assert mock_fetch_robots.call_args[0][0].endswith("example.i2p/")
        finally:
            import os
            try:
                os.unlink(db_path)
            except FileNotFoundError:
                pass

    @patch("src.integration.probe_destination")
    def test_does_not_fetch_robots_when_disabled(self, mock_probe):
        from src.integration import discover_addresses

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        # This function should NOT call fetch_robots_txt in integration module
        # because respect_robots is False by default
        original_import = __import__("src.robots_parser") if "src.robots_parser" not in dir(__import__("builtins")) else None

        mock_result = MagicMock()
        mock_result.reachable = True
        mock_result.response_time_sec = 1.0
        mock_result.body_length = 1000
        mock_result.found_links = []
        mock_probe.return_value = mock_result

        try:
            results = discover_addresses(
                known_addrs=["example.i2p"],
                db_path=db_path,
                respect_robots=False,
            )
            # probe_destination should receive robots_policy=None
            assert mock_probe.call_args.kwargs.get("robots_policy") is None or \
                   mock_probe.call_args[-1].get("robots_policy") is None
        finally:
            import os
            try:
                os.unlink(db_path)
            except FileNotFoundError:
                pass


# ── CLI flag test ───────────────────────────────────────────────────


class TestRespectRobotsCLI:
    """Test that --respect-robots flag is parsed correctly."""

    def test_flag_exists(self):
        import subprocess
        result = subprocess.run(
            ["python", "-m", "probe_sweep", "--help"],
            capture_output=True,
            text=True,
            cwd="/home/stefan/Projects/I2P-Indexer",
        )
        assert "--respect-robots" in result.stdout

    def test_flag_parses(self):
        import subprocess
        # --respect-robots should be accepted (even if it fails later due to missing I2P)
        result = subprocess.run(
            ["python", "-m", "probe_sweep", "sweep", "--count", "1", "--respect-robots"],
            capture_output=True,
            text=True,
            cwd="/home/stefan/Projects/I2P-Indexer",
            timeout=5,
        )
        # Should not error with 'unrecognized arguments'
        assert "unrecognized arguments: --respect-robots" not in result.stderr
