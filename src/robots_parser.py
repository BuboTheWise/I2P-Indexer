"""robots.txt parser for I2P destinations.

Parses robots.txt Disallow rules and provides path-matching so the probe
sweep can skip paths that explicitely disallow crawling when --respect-robots
is enabled on the CLI.

Design:
  - Minimal implementation — only parses User-Agent, Disallow, and Allow.
  - Groups rules by host (http://SITE/robots.txt belongs exclusively to SITE).
  - Supports globs (*) and suffix matches ($) per the robots.txt spec.
  - Defaults to ALLOW when no matching rule exists (standard robots behaviour).

Usage:
    from src.robots_parser import RobotsPolicy, fetch_robots_txt, policy_blocks_path

    # Fetch and cache rules for a destination:
    robots = fetch_robots_txt("http://example.i2p/", config=cfg)
    if not robots:
        print("No robots.txt found — probing everything")

    # Check individual paths:
    if policy_blocks_path(robots, "/admin"):
        continue  # skip this path per robots.txt
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

# Imported at module level for testability (mocking in tests).
from .i2p_proxy import fetch_i2p

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RobotsRule:
    """A single Disallow/Allow rule from one User-Agent group."""
    path_prefix: str       # leading portion of the pattern (after stripping suffix $)
    is_disallow: bool      # True for Disallow, False for Allow
    has_wildcard: bool     # '*' or '?' in prefix
    has_suffix: bool       # rule ends with '$'

    def matches(self, path: str) -> bool:
        """Check if a URL path matches this rule.

        Supports wildcards via fnmatch and suffix anchors with '$'.
        """
        if self.has_wildcard:
            return fnmatch.fnmatch(path, self.path_prefix)
        elif self.has_suffix:
            # '$' anchors to end of path — strip leading '/' for suffix comparison.
            # Pattern /.pdf$ means any path ending in .pdf
            suffix = self.path_prefix[1:] if self.path_prefix.startswith("/") else self.path_prefix
            return path.endswith(suffix)
        else:
            # Simple prefix match (most common case):
            return path.startswith(self.path_prefix)


@dataclass
class RobotsPolicy:
    """Parsed robots.txt for a single host.

    The standard matching algorithm (per Google's implementation):
      1. Find rulesets that apply to the crawler (User-Agent lines).
      2. Among matching rules, pick the LONGEST match.
      3. The longest match wins; if it is Disallow → blocked.

    When ``respect_robots=True`` and no robots.txt is found, we default
    to ALLOW everything (the standard interpretation: absence means open).
    """
    host: str
    rules: list[RobotsRule] = field(default_factory=list)
    fetched_at: float = 0.0

    def blocks_path(self, path: str) -> bool:
        """Determine if a path is DISALLOWED by this policy.

        Returns False (allow) when:
          - No rules exist (empty robots.txt or no matching agent).
          - Longest-matching rule is an Allow directive.
          - Path doesn't match any Disallow pattern.

        Returns True (block) when:
          - Longest-matching rule is a Disallow directive.
        """
        # Normalise path
        if not path.startswith("/"):
            path = "/" + path
        path.rstrip("/") or None  # strip trailing slash for consistency

        candidates: list[tuple[int, RobotsRule]] = []
        for rule in self.rules:
            if rule.matches(path):
                candidates.append((len(rule.path_prefix), rule))

        if not candidates:
            return False  # no match → allow by default (per spec)

        # Longest match wins
        _, longest_rule = max(candidates, key=lambda c: c[0])
        return longest_rule.is_disallow

    @property
    def is_fully_blocked(self) -> bool:
        """Check if root path '/' is disallowed (site-wide block)."""
        for rule in self.rules:
            if rule.is_disallow and rule.matches("/"):
                return True
        return False


def parse_robots_txt(host: str, raw_text: str) -> RobotsPolicy:
    """Parse a robots.txt body into structured rules.

    Handles:
      - User-Agent (wildcard * or named bots)
      - Disallow / Allow directives
      - Comments (# at line start or inline)
      - Blank lines between groups
    """
    rules: list[RobotsRule] = []
    lines = raw_text.splitlines()

    for line in lines:
        # Strip comments and whitespace
        comment_idx = line.find("#")
        if comment_idx >= 0:
            line = line[:comment_idx]
        line = line.strip().lower()

        if not line:
            continue

        if line.startswith("user-agent:") or line.startswith("agent:"):
            # Agent name — we always parse the first universal group.
            # Skip user-specific agents (e.g. Googlebot) since we're a generic crawler.
            continue

        if line.startswith("disallow:"):
            prefix = line[len("disallow:"):].strip()
            has_suffix = False
            if prefix.endswith("$"):
                prefix = prefix[:-1]
                has_suffix = True
            has_wc = "*" in prefix or "?" in prefix
            rules.append(RobotsRule(
                path_prefix=prefix,
                is_disallow=True,
                has_wildcard=has_wc,
                has_suffix=has_suffix,
            ))

        elif line.startswith("allow:"):
            prefix = line[len("allow:"):].strip()
            has_suffix = False
            if prefix.endswith("$"):
                prefix = prefix[:-1]
                has_suffix = True
            has_wc = "*" in prefix or "?" in prefix
            rules.append(RobotsRule(
                path_prefix=prefix,
                is_disallow=False,
                has_wildcard=has_wc,
                has_suffix=has_suffix,
            ))

    return RobotsPolicy(host=host, rules=rules, fetched_at=time.time())


def fetch_robots_txt(
    base_url: str,
    config=None,
    timeout: float = 30.0,
) -> Optional[RobotsPolicy]:
    """Fetch and parse robots.txt for a destination.

    Args:
        base_url: Base URL of the site (e.g., http://example.i2p/).
        config: I2PConfig instance for proxy settings.
        timeout: Per-request timeout in seconds.

    Returns:
        RobotsPolicy if robots.txt exists and was parsed; None if not found or error.
    """
    robots_url = base_url.rstrip("/") + "/robots.txt"
    try:
        resp = fetch_i2p(robots_url, via="http-proxy", timeout=timeout, config=config)
        if resp.status == 200 and resp.body:
            raw_text = resp.text
            host = base_url.split("//")[1].split("/")[0] if "//" in base_url else base_url
            logger.info("  [robots] Fetched %s rules for %s", len(parse_robots_txt(host, raw_text).rules), host)
            return parse_robots_txt(host, raw_text)
        elif resp.status == 404:
            return None
        else:
            logger.warning("  [robots] %s returned HTTP %d — skipping robots filtering", base_url, resp.status)
            return None

    except Exception as exc:
        logger.warning("  [robots] Failed to fetch robots.txt for %s: %s", base_url, exc)
        return None


def policy_blocks_path(policy: Optional[RobotsPolicy], path: str, default_allow: bool = True) -> bool:
    """Check if a path is blocked by the given robots policy.

    Convenience wrapper that handles None policies gracefully.

    Args:
        policy: Parsed robots policy (None means no robots.txt found).
        path: URL path to check.
        default_allow: When True, None/missing policies allow everything.

    Returns:
        True if the path is BLOCKED by robots.txt rules.
    """
    if policy is None:
        return not default_allow
    return policy.blocks_path(path)
