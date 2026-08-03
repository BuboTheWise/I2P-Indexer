"""I2P network health detection via the router console API.

Reads router state from the webconsole (/home, /peers, /tunnels) to
determine if the I2P network is ready for probing before we start pounding
it with requests.  This prevents wasteful probe runs when the router is
still booting or has tunnel failures.

Data points:
- Router version & uptime
- Peer count (connected vs target)  — primary readiness signal
- Client/server tunnel counts       — actual tunnel health
- Bandwidth in/out                  — activity indicator
- NetDB / address book size         — how many destinations are known

Notes on the console API (I2P router 2.13.x):
- The webconsole is behind a login screen but can be accessed anonymously
  via session cookie auto-provisioning.
- localhost:7657 redirects to Docker container IP; we handle this via
  HTTPCookieProcessor which tracks the session across redirects.
- /tunnel/summary returns 404 on some router builds — use /home + /peers instead.
"""
from __future__ import annotations

import logging
import re
import time
import urllib.error
import urllib.request
import http.cookiejar
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class I2PHealth:
    """Snapshot of I2P router health at a point in time."""

    # Router identity
    version: str = ""
    uptime_seconds: float = 0.0

    # Peer connections — primary readiness signal
    peers_connected: int = 0
    peers_target: int = 0

    # Tunnel counts
    client_tunnels_established: int = 0
    server_tunnels_running: int = 0
    tunnels_failed: int = 0

    # Bandwidth (KBps)
    bandwidth_in_kbps: float = 0.0
    bandwidth_out_kbps: float = 0.0

    # Network database
    netdb_known: int = 0
    floodfill_routers: int = 0

    @property
    def readiness_score(self) -> float:
        """0..1 readiness score from the available metrics."""
        peer_ratio = min(1.0, self.peers_connected / max(self.peers_target, 10))
        tunnel_ok = min(1.0, self.client_tunnels_established / max(2, 1))
        uptime_bonus = min(1.0, self.uptime_seconds / 300)
        return peer_ratio * 0.4 + tunnel_ok * 0.4 + uptime_bonus * 0.2

    @property
    def is_ready(self) -> bool:
        """True when we can reasonably expect probes to succeed."""
        return (self.readiness_score >= 0.3 and
                self.peers_connected >= 8 and
                self.client_tunnels_established >= 2)

    @property
    def status_label(self) -> str:
        if self.readiness_score < 0.1:
            return "down"
        if self.readiness_score < 0.3:
            return "booting"
        if self.readiness_score < 0.6:
            return "reconnecting"
        return "ready"

    def summary(self) -> str:
        lines = [
            f"I2P Health [{self.status_label}] (score={self.readiness_score:.1f})",
            f"  Version:   {self.version}",
            f"  Uptime:    {self.uptime_seconds:.0f}s",
            f"  Peers:     {self.peers_connected}/{self.peers_target}",
            f"  Client tunnels: {self.client_tunnels_established} (failed: {self.tunnels_failed})",
            f"  Server tunnels: {self.server_tunnels_running}",
            f"  Bandwidth: {self.bandwidth_in_kbps:.1f}/{self.bandwidth_out_kbps:.1f} KB/s",
            f"  NetDB known: {self.netdb_known}, floodfill: {self.floodfill_routers}",
            f"  Readiness: {'READY' if self.is_ready else 'NOT YET'}",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML parsing helpers — the console returns raw HTML, not JSON
# ---------------------------------------------------------------------------

_KB_RE = re.compile(r"([\d.]+)\s*/\s*([\d.]+)")
_UPTIME_RE = re.compile(
    r"(\d+)\s*(?:min|mins?)"
    r"(?:\s*,?\s*(\d+)\s*(?:sec|secs?))?"
)


def _parse_td_cells(html: str) -> list[str]:
    """Extract all <td> cell text from console HTML, stripping tags and entities."""
    cells = re.findall(r"<td[^>]*>(.*?)</td>", html, re.DOTALL | re.IGNORECASE)
    result = []
    for c in cells:
        # Strip HTML tags first
        text = re.sub(r"<[^>]+>", "", c)
        # Replace common HTML entities
        text = text.replace("&nbsp;", " ").replace("\u00a0", " ")
        result.append(text.strip())
    return result


def _parse_uptime(text: str) -> float:
    """Parse uptime string like '27 min' into seconds."""
    m = re.search(r"(\d+)\s*min\b", text, re.IGNORECASE)
    if m:
        total = int(m.group(1)) * 60
        sm = re.search(r"(\d+)\s*sec\b", text, re.IGNORECASE)
        if sm:
            total += int(sm.group(1))
        return total
    return 0.0


def _fetch_console_page(opener, path: str) -> list[str]:
    """Fetch a console page and return stripped <td> cell text.

    Raises urllib.error on failure.
    """
    html = opener.open(f"{BASE_URL}{path}", timeout=10).read().decode(
        "utf-8", errors="replace"
    )
    return _parse_td_cells(html)


# Base URL — configurable at class level to allow Docker vs localhost override
BASE_URL = "http://127.0.0.1:7657"


def check_i2p_health(
    console_host: str | None = None,
    console_port: int | None = None,
) -> I2PHealth:
    """Query the router console for health metrics.

    Returns an ``I2PHealth`` snapshot.
    Raises ``ConnectionError`` if the console is unreachable.

    The console pages return HTML tables where each row has
    label-cell then value-cell.  We parse all <td> elements from
    /home (version, uptime, bandwidth) and /peers (peer counts, tunnels).
    """
    global BASE_URL
    url = f"http://{console_host or '127.0.0.1'}:{console_port or 7657}"
    was_overridden = console_host is not None or console_port is not None

    # Build opener with cookie jar (auto-provisions session)
    cj = http.cookiejar.CookieJar()
    handler = urllib.request.HTTPCookieProcessor(cj)
    opener = urllib.request.build_opener(handler)

    temp_base = url  # local ref for this call
    if was_overridden:
        BASE_URL = temp_base

    try:
        health = I2PHealth()

        # /home gives version, uptime, bandwidth
        home_cells = _fetch_console_page(opener, "/home")

        # Parse version (cell [1] in sb_general table)
        if len(home_cells) > 1:
            health.version = home_cells[1]

        # Uptime is cell [3] "XX min" or "XX min Y sec"
        if len(home_cells) > 3:
            health.uptime_seconds = _parse_uptime(home_cells[3])

        # Bandwidth in/out is cell [5] "X / Y KBps"
        if len(home_cells) > 5:
            mw = _KB_RE.search(home_cells[5])
            if mw:
                health.bandwidth_in_kbps = float(mw.group(1))
                health.bandwidth_out_kbps = float(mw.group(2))

        # /peers gives peer counts + tunnel info
        peers_cells = _fetch_console_page(opener, "/peers")

        # Active peers at cell [20] "N / M" (connected / target)
        if len(peers_cells) > 20:
            pm = _KB_RE.search(peers_cells[20])
            if pm:
                health.peers_connected = int(pm.group(1))
                health.peers_target = int(pm.group(2))

        # Client tunnels at cell [32]
        if len(peers_cells) > 32:
            try:
                health.client_tunnels_established = int(peers_cells[32])
            except ValueError:
                dm = re.search(r"\d+", peers_cells[32])
                if dm:
                    health.client_tunnels_established = int(dm.group(0))

        # NetDB known routers at cell [28]
        if len(peers_cells) > 28:
            try:
                health.netdb_known = int(peers_cells[28])
            except ValueError:
                pass

        # Floodfill routers at cell [26]
        if len(peers_cells) > 26:
            try:
                health.floodfill_routers = int(peers_cells[26])
            except ValueError:
                pass

        # Server tunnels — estimate from NTCP2+SSU2 counts (cells [41], [46])
        if len(peers_cells) > 45:
            try:
                ntcp = int(peers_cells[41]) if peers_cells[41].isdigit() else 0
                ssu = int(peers_cells[46]) if peers_cells[46].isdigit() else 0
                health.server_tunnels_running = max(ntcp, ssu)
            except (ValueError, IndexError):
                pass

    except urllib.error.URLError as e:
        raise ConnectionError(
            f"I2P console at {temp_base} unreachable: {e.reason}"
        ) from e

    return health


# ---------------------------------------------------------------------------
# Wait-until-ready helper — blocks until the router passes readiness check
# ---------------------------------------------------------------------------

def wait_for_i2p_ready(
    console_host: str | None = None,
    console_port: int | None = None,
    timeout: float = 600.0,
    poll_interval: float = 30.0,
) -> I2PHealth:
    """Poll the router until it's ready for probing.

    Returns ``I2PHealth`` when ready, raises ``TimeoutError`` after *timeout*
    seconds, or ``ConnectionError`` if the console went away entirely.
    """
    deadline = time.monotonic() + timeout
    last_report = time.monotonic()

    while time.monotonic() < deadline:
        try:
            health = check_i2p_health(console_host, console_port)
        except ConnectionError:
            if time.monotonic() - last_report > poll_interval:
                logger.warning("I2P console unreachable")
                last_report = time.monotonic()
            time.sleep(min(10, deadline - time.monotonic()))
            continue

        # Log progress periodically
        if time.monotonic() - last_report > poll_interval:
            logger.info("%s", health.summary())
            last_report = time.monotonic()

        if health.is_ready:
            logger.info("I2P ready — %s", health.summary())
            return health

        remaining = max(deadline - time.monotonic(), 5)
        time.sleep(min(remaining, poll_interval))

    # Final attempt on deadline
    try:
        health = check_i2p_health(console_host, console_port)
        if health.is_ready:
            return health
    except ConnectionError:
        pass

    raise TimeoutError(
        f"I2P network not ready after {timeout:.0f}s"
    )


# ---------------------------------------------------------------------------
# CLI entry point — quick health check from terminal
# ---------------------------------------------------------------------------

def _main() -> int:
    try:
        health = check_i2p_health()
        print(health.summary())
        return 0
    except ConnectionError as e:
        print(f"I2P console unreachable: {e}")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(_main())
