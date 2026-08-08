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


# ── End-to-end: robots policy filters discovered links from HTML ─────


class TestRobotsFiltersDiscoveredLinks:
    """Test that Disallow rules actually drop .i2p links extracted from mocked HTML.

    Tests the wire-up path: discover_addresses() -> probe_destination() -> _do_probe()
    where _do_probe fetches HTML via fetch_i2p, the HtmlExtractor extracts .i2p
    hostnames from <a> tags / body text, and robots_policy filters them at result
    assembly time.  Uses full mock responses with known disallowed/allowed paths."""

    @patch("src.integration.fetch_i2p")
    def test_fully_blocked_robots_drops_all_discovered_links(self, mock_fetch):
        """When robots.txt Disallow: / (fully blocked), ALL .i2p links extracted from
        the mocked HTML must be removed from result.found_links."""
        from src.integration import probe_destination

        # Mock HTML containing several .i2p links in <a> tags and body text
        mock_html = (
            "<html><head><title>Test Site</title></head>"
            "<body>"
            '  <p>Welcome to our site.</p>'
            '  <a href="http://alice-market.i2p/">Alice Market</a>'
            '  <a href="http://bob-forum.i2p/">Bob Forum</a>'
            '  <a href="http://carol-blog.i2p/">Carol Blog</a>'
            '  Also check charlie-wiki.i2p and dave-archive.i2p'
            "</body></html>"
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = mock_html.encode("utf-8")
        mock_resp.text = mock_html
        mock_resp.title = MagicMock(return_value="Test Site")
        mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_fetch.return_value = mock_resp

        # Robots policy that blocks EVERYTHING (Disallow: /)
        from src.robots_parser import parse_robots_txt
        robots_raw = "User-agent: *\nDisallow: /\n"
        full_block_policy = parse_robots_txt("test.i2p", robots_raw)
        assert full_block_policy.is_fully_blocked

        result = probe_destination(
            ident_hash_hex="aabbccddee" * 4,  # 40-char hex -> valid b32 address
            i2p_dns_name="test.i2p",
            robots_policy=full_block_policy,
        )

        # The extractor SHOULD have found .i2p links in the HTML,
        # but the robots filter must remove all of them.
        assert result.reachable is True
        # All discovered i2p links must be blocked
        assert len(result.found_links) == 0, (
            f"Expected no links when fully blocked, got: {result.found_links}"
        )

    @patch("src.integration.fetch_i2p")
    def test_partial_disallow_allows_hostname_links(self, mock_fetch):
        """When robots.txt has partial Disallow rules (e.g. /admin), extracted .i2p
        hostname links are NOT filtered (since hostnames != paths).

        This documents current behavior: path-level Disallow only triggers link
        removal when is_fully_blocked=True."""
        from src.integration import probe_destination

        mock_html = (
            "<html><head><title>Test Site</title></head>"
            "<body>"
            '  <p>Welcome.</p>'
            '  <a href="http://neighbor-site.i2p/">Neighbor</a>'
            '  <a href="http://other-market.i2p/">Other Market</a>'
            "</body></html>"
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = mock_html.encode("utf-8")
        mock_resp.text = mock_html
        mock_resp.title = MagicMock(return_value="Test Site")
        mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_fetch.return_value = mock_resp

        # Partial disallow — blocks /admin but not everything
        from src.robots_parser import parse_robots_txt
        robots_raw = "User-agent: *\nDisallow: /admin\nDisallow: /private\n"
        partial_policy = parse_robots_txt("test.i2p", robots_raw)
        assert not partial_policy.is_fully_blocked

        result = probe_destination(
            ident_hash_hex="aabbccddee" * 4,
            i2p_dns_name="test.i2p",
            robots_policy=partial_policy,
        )

        # With partial disallow, hostname-level .i2p links pass through
        assert result.reachable is True
        # Links should be present (they're hostnames, not paths)
        assert len(result.found_links) > 0, (
            f"Expected links to pass through with partial disallow, got: {result.found_links}"
        )

    @patch("src.integration.fetch_i2p")
    def test_discover_addresses_respects_robots_via_probe(self, mock_fetch):
        """Full integration: discover_addresses with respect_robots=True should produce
        results where fully-blocked sites have no discovered links and carry a robots_txt flag."""
        from src.integration import discover_addresses

        mock_html = (
            "<html><head><title>Blocked Site</title></head>"
            "<body>"
            '  <a href="http://seed1.i2p/">Seed 1</a>'
            '  <a href="http://seed2.i2p/">Seed 2</a>'
            '  <a href="http://seed3.i2p/">Seed 3</a>'
            "</body></html>"
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = mock_html.encode("utf-8")
        mock_resp.text = mock_html
        mock_resp.title = MagicMock(return_value="Blocked Site")
        mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_fetch.return_value = mock_resp

        # Patch fetch_robots_txt to return a fully-blocked policy for this destination
        with patch("src.robots_parser.fetch_robots_txt") as mock_fetch_robots:
            from src.robots_parser import parse_robots_txt
            block_all = parse_robots_txt("blocked.i2p", "User-agent: *\nDisallow: /\n")
            mock_fetch_robots.return_value = block_all

            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
                db_path = f.name

            try:
                results = discover_addresses(
                    known_addrs=["blocked.i2p"],
                    db_path=db_path,
                    respect_robots=True,
                )
                assert len(results) == 1
                r = results[0]
                # Discovered links must be empty (blocked by robots policy)
                assert len(r.found_links) == 0, (
                    f"Expected no links from blocked site, got: {r.found_links}"
                )
                # A robots_txt flag must exist in the result flags
                robot_flags = [f for f in r.flags if f.get("type") == "robots_txt"]
                assert len(robot_flags) > 0, (
                    f"Expected a robots_txt flag in flags: {r.flags}"
                )
                # The flag should reference blocked links
                flag_value = robot_flags[0].get("value", "")
                assert "blocked" in flag_value.lower(), (
                    f"Flag value should mention 'blocked': {flag_value}"
                )

            finally:
                import os
                try:
                    os.unlink(db_path)
                except FileNotFoundError:
                    pass

    @patch("src.integration.fetch_i2p")
    def test_no_robots_policy_preserves_discovered_links(self, mock_fetch):
        """Without robots policy (respect_robots=False), all .i2p links from HTML
        should be preserved in the result."""
        from src.integration import probe_destination

        mock_html = (
            "<html><head><title>No Robots</title></head>"
            "<body>"
            '  <a href="http://link-a.i2p/">A</a>'
            '  <a href="http://link-b.i2p/">B</a>'
            '  Reference: link-c.i2p'
            "</body></html>"
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = mock_html.encode("utf-8")
        mock_resp.text = mock_html
        mock_resp.title = MagicMock(return_value="No Robots")
        mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_fetch.return_value = mock_resp

        result = probe_destination(
            ident_hash_hex="aabbccddee" * 4,
            i2p_dns_name="norobots.i2p",
            robots_policy=None,  # equivalent to respect_robots=False
        )

        assert result.reachable is True
        # All .i2p links should be present without filtering
        assert len(result.found_links) >= 3, (
            f"Expected at least 3 discovered i2p links, got: {result.found_links}"
        )
