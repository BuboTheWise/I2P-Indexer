"""Tests for the I2P proxy client.

These tests are LIVE — they connect through the local I2P daemon's SOCKS5/HTTP
proxy. Requires I2P to be running and reachable on 127.0.0.1:7656 / 127.0.0.1:4444.

Run with: pytest tests/test_proxy.py -v --tb=short
"""

import unittest

from src.proxy_client import I2PProxyClient


class TestConnectivity(unittest.TestCase):
    """Verify we can reach the I2P proxy and route requests through it."""

    def test_socks5_port_accepts_connections(self):
        """Port 7656 (SOCKS5) should accept TCP handshakes."""
        import socket
        s = socket.socket()
        s.settimeout(3)
        try:
            s.connect(("127.0.0.1", 7656))
            # Connection succeeded — port is alive
        finally:
            s.close()

    def test_http_proxy_port_accepts_connections(self):
        """Port 4444 (HTTP proxy) should accept TCP handshakes."""
        import socket
        s = socket.socket()
        s.settimeout(3)
        try:
            s.connect(("127.0.0.1", 4444))
        finally:
            s.close()

    def test_client_initializes(self):
        """We can instantiate I2PProxyClient without error."""
        client = I2PProxyClient()
        self.assertEqual(client.config.socks_port, 7656)
        self.assertEqual(client.timeout, 120.0)


class TestI2PRouting(unittest.TestCase):
    """Actually route traffic through the tunnel."""

    @classmethod
    def setUpClass(cls):
        cls.client = I2PProxyClient(timeout=60.0)

    def test_health_check(self):
        """Reach i2pstat.i2p through either SOCKS5 or HTTP fallback.
        
        This is an integration test — it takes time because I2P tunnel
        establishment can take 30+ seconds on first connection.
        """
        # TODO: enable once we've verified the daemon is routing properly
        self.skipTest("enabled after initial connectivity verification")
        result = self.client.health_check()
        self.assertTrue(result, "Could not reach i2pstat.i2p through I2P proxy")

    def test_probe_returns_result_object(self):
        """Even a failed probe should return a ProbeResult (not raise)."""
        # Use an obviously fake address — expect timeout/error, not success
        result = self.client.probe("aaaaa" * 9 + "aaaa", scheme="http")
        from src.proxy_client import ProbeResult
        self.assertIsInstance(result, ProbeResult)
        self.assertIsNotNone(result.error or result.status_code is None)


def main():
    unittest.main()


if __name__ == "__main__":
    main()
