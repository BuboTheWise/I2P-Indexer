"""SOCKS5 and HTTP proxy client for I2P tunnels.

All connections flow through the local I2P daemon — no direct outbound traffic,
no browser dependencies. Pure httpx + pysocks.
"""

import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from .config import I2PConfig

logger = logging.getLogger(__name__)


@dataclass
class ProbeResult:
    """Result of probing a single destination."""
    address: str
    status_code: Optional[int]
    content_length: int = 0
    response_time: float = 0.0
    title: Optional[str] = None
    error: Optional[str] = None

    @property
    def reachable(self) -> bool:
        return self.status_code is not None and self.status_code < 500


class I2PProxyClient:
    """HTTP client routed through the local I2P proxy."""

    def __init__(self, config: Optional[I2PConfig] = None, timeout: float = 120.0):
        self.config = config or I2PConfig()
        self.timeout = timeout

    # --- SOCKS5 HTTP tunnel via httpx ---

    def _socks_transport(self) -> httpx.HTTPTransport:
        """Create an httpx transport that routes through the local SOCKS5 proxy."""
        return httpx.HTTPTransport(
            proxy=f"socks5://{self.config.socks_host}:{self.config.socks_port}"
        )

    def _http_client(self) -> httpx.Client:
        """Return a configured httpx client bound to the I2P SOCKS5 proxy."""
        return httpx.Client(
            transport=self._socks_transport(),
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
            max_redirects=10,
        )

    def _client_via_http_proxy(self) -> httpx.Client:
        """Fallback: use the HTTP CONNECT proxy instead of SOCKS5."""
        return httpx.Client(
            proxy=f"http://{self.config.http_host}:{self.config.http_port}",
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
            max_redirects=10,
        )

    # --- Public API ---

    def health_check(self) -> bool:
        """Verify that the I2P proxy is alive and accepting connections.

        Tries to reach a well-known I2P destination through the tunnel.
        If this succeeds, the daemon is connected and routing traffic.
        """
        # i2pstat.i2p is a well-known monitoring site
        try:
            with self._http_client() as client:
                resp = client.get("http://i2pstat.i2p/", timeout=30)
                logger.info(
                    "SOCKS5 health check: HTTP %d, contentLength=%s",
                    resp.status_code, len(resp.content),
                )
                return True
        except Exception as exc:
            # Fall back to HTTP proxy
            try:
                with self._client_via_http_proxy() as client:
                    resp = client.get("http://i2pstat.i2p/", timeout=30)
                    logger.info(
                        "HTTP proxy health check: HTTP %d, contentLength=%s",
                        resp.status_code, len(resp.content),
                    )
                    return True
            except Exception as e:
                logger.error("Health check failed via both SOCKS5 and HTTP proxy: %s — %s", exc, e)
                return False

    def probe(self, base32_address: str, scheme: str = "http") -> ProbeResult:
        """Attempt to reach an eepsite by its base32 address.

        Args:
            base32_address: The 52-char base32 destination hash (without .i2p).
            scheme: http or https.
        """
        url = f"{scheme}://{base32_address}.i2p/"
        logger.debug("Probing %s via I2P proxy", url)

        import time
        start = time.monotonic()

        try:
            with self._http_client() as client:
                resp = client.get(url, timeout=self.timeout)
                elapsed = time.monotonic() - start

                # Try to extract title from HTML body
                title = None
                raw = resp.text[:8000]  # only look at first 8KB for performance
                if "<title>" in raw.lower():
                    import re
                    m = re.search(r"<title[^>]*>(.*?)</title>", raw, re.IGNORECASE | re.DOTALL)
                    if m:
                        title = m.group(1).strip().strip()

                return ProbeResult(
                    address=base32_address,
                    status_code=resp.status_code,
                    content_length=len(resp.content),
                    response_time=round(elapsed, 2),
                    title=title,
                )

        except httpx.TimeoutException:
            elapsed = time.monotonic() - start
            return ProbeResult(
                address=base32_address,
                status_code=None,
                response_time=round(elapsed, 2),
                error=f"timeout after {elapsed:.1f}s",
            )
        except Exception as e:
            elapsed = time.monotonic() - start
            logger.warning("Probe failed for %s: %s", base32_address, e)
            return ProbeResult(
                address=base32_address,
                status_code=None,
                response_time=round(elapsed, 2),
                error=str(e)[:500],
            )

    def probe_http_fallback(self, base32_address: str) -> ProbeResult:
        """Same as probe() but forces the HTTP CONNECT proxy instead of SOCKS5."""
        url = f"http://{base32_address}.i2p/"
        logger.debug("Falling back to HTTP proxy for %s", url)

        import time
        start = time.monotonic()

        try:
            with self._client_via_http_proxy() as client:
                resp = client.get(url, timeout=self.timeout)
                elapsed = time.monotonic() - start
                return ProbeResult(
                    address=base32_address,
                    status_code=resp.status_code,
                    content_length=len(resp.content),
                    response_time=round(elapsed, 2),
                )
        except Exception as e:
            elapsed = time.monotonic() - start
            return ProbeResult(
                address=base32_address,
                status_code=None,
                response_time=round(elapsed, 2),
                error=str(e)[:500],
            )
