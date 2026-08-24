"""SOCKS5 and HTTP proxy client for I2P tunnels.

All connections flow through the local I2P daemon — no direct outbound traffic,
no browser dependencies. Pure httpx + pysocks.
"""

import logging
from typing import Optional

import httpx

from .config import I2PConfig

logger = logging.getLogger(__name__)


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


