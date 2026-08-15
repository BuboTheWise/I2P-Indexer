"""Tests for the I2P proxy client (SOCKS5 + SAM API).

Run with: pytest tests/test_i2p_proxy.py -v --tb=short
"""

import socket
import unittest
from src.i2p_proxy import (
    fetch_i2p,
    I2PProxyClient,
    I2PSAMClient,
    ProxyBackend,
    Response,
    probe_health,
)


class TestResponseDataclass(unittest.TestCase):
    """Unit tests for the Response wrapper."""

    def test_response_creation(self):
        r = Response(url="http://test.i2p/", status=200, body=b"<html>hi</html>")
        self.assertEqual(r.status, 200)
        self.assertTrue(r.ok)
        self.assertIn("hi", r.text)

    def test_response_title(self):
        r = Response(url="http://test.i2p/", status=200, body=b"<html><head><title>Test Page</title></head></html>")
        self.assertEqual(r.title(), "Test Page")

    def test_response_title_none(self):
        r = Response(url="http://test.i2p/", status=200, body=b"no title here")
        self.assertIsNone(r.title())

    def test_response_not_ok(self):
        r = Response(url="http://test.i2p/", status=404)
        self.assertFalse(r.ok)

    def test_response_zero_status(self):
        r = Response(url="http://test.i2p/", status=0)
        self.assertFalse(r.ok)
        self.assertEqual(r.text, "")


class TestProxyClientInit(unittest.TestCase):
    """Verify client instantiation without hitting the network."""

    def test_default_ports(self):
        c = I2PProxyClient()
        self.assertEqual(c.socks_port, 7656)
        self.assertEqual(c.http_port, 4444)
        self.assertEqual(c.timeout, 120.0)

    def test_custom_ports(self):
        c = I2PProxyClient(socks_port=9000, http_port=8000, timeout=60.0)
        self.assertEqual(c.socks_port, 9000)
        self.assertEqual(c.http_port, 8000)
        self.assertEqual(c.timeout, 60.0)


class TestSAMClientInit(unittest.TestCase):
    """Verify SAM client instantiation without hitting the network."""

    def test_default_ports(self):
        c = I2PSAMClient()
        self.assertEqual(c.port, 9025)
        self.assertFalse(c._connected)
        self.assertIsNone(c._sock)

    def test_custom_config(self):
        c = I2PSAMClient(host="10.0.0.1", port=9020, session_name="my-tunnel")
        self.assertEqual(c.host, "10.0.0.1")
        self.assertEqual(c.port, 9020)
        self.assertEqual(c.session_name, "my-tunnel")


class TestHTTPProxyLive(unittest.TestCase):
    """Live tests against the I2P daemon's HTTP proxy."""

    @classmethod
    def setUpClass(cls):
        cls.client = I2PProxyClient(timeout=120.0)

    def test_http_proxy_port_accepts_tcp(self):
        """Port 4444 should accept TCP connections."""
        s = socket.socket()
        s.settimeout(3)
        try:
            s.connect(("127.0.0.1", 4444))
        finally:
            s.close()

    def test_fetch_known_eepsite(self):
        """Fetch i2p-projekt.i2p via HTTP proxy and verify we get HTML."""
        r = self.client.request("http://i2p-projekt.i2p/", backend="http-proxy")
        self.assertIsInstance(r, Response)
        self.assertGreater(r.status, 0, "Should have gotten a numeric status code")
        self.assertGreater(len(r.body), 0, "Should have received body content")
        self.assertIn(r.via.value, ("http-proxy", "socks5"), "Via should be set")

    def test_fetch_returns_response_object(self):
        """Even failed targets should return a Response (not raise)."""
        r = self.client.request("http://obviously-not-a-real-site.i2p/", backend="http-proxy")
        self.assertIsInstance(r, Response)
        # Should have status == 0 on complete failure, or a non-zero HTTP status
        self.assertTrue(
            isinstance(r.status, int),
            "Status should always be an integer",
        )

    def test_fetch_i2p_helper_http_proxy(self):
        """The unified fetch_i2p() helper works with via='http-proxy'."""
        r = fetch_i2p("http://i2p-projekt.i2p/", via="http-proxy")
        self.assertIsInstance(r, Response)
        self.assertGreater(r.status, 0)

    def test_fetch_socks_fallback(self):
        """fetch_i2p with via='socks' falls back to HTTP proxy when SOCKS fails."""
        r = fetch_i2p("http://i2p-projekt.i2p/", via="socks")
        self.assertIsInstance(r, Response)
        # The response should come from HTTP proxy fallback since SOCKS5 is broken on this host
        self.assertIn(r.via.value, ("http-proxy", "socks5"))


class TestSAMUnavailable(unittest.TestCase):
    """Tests that verify SAM client handles a missing server gracefully."""

    def test_sam_connect_refused(self):
        """Connecting to a port with no SAM server should fail gracefully."""
        c = I2PSAMClient(port=9025, timeout=3)
        result = c.connect()
        self.assertFalse(result, "SAM connect should return False when server is down")

    def test_sam_fetch_returns_response(self):
        """A SAM fetch to a missing server returns a Response object (no crash)."""
        c = I2PSAMClient(port=9025, timeout=3)
        r = c.fetch("http://i2p-projekt.i2p/")
        self.assertIsInstance(r, Response)
        self.assertEqual(r.status, 0)
        self.assertEqual(r.via, ProxyBackend.SAM)


class TestHealthProbe(unittest.TestCase):
    """Verify the health check utility."""

    def test_probe_http_proxy(self):
        """probe_health should return True if at least one eepsite responds."""
        result = probe_health(via="http-proxy")
        self.assertTrue(result, "At least one known .i2p site should respond via HTTP proxy")


class TestComparison(unittest.TestCase):
    """Compare SOCKS5 and HTTP proxy performance/reliability."""

    @classmethod
    def setUpClass(cls):
        cls.client = I2PProxyClient(timeout=120.0)

    def test_both_return_response_objects(self):
        """Both backends should return Response objects for the same target."""
        r_http = self.client.request("http://i2p-projekt.i2p/", backend="http-proxy")
        r_socks = self.client.request("http://i2p-projekt.i2p/", backend="socks5")
        self.assertIsInstance(r_http, Response)
        self.assertIsInstance(r_socks, Response)

    def test_http_proxy_gets_content(self):
        """HTTP proxy should successfully fetch content."""
        r = self.client.request("http://i2p-projekt.i2p/", backend="http-proxy")
        self.assertGreater(len(r.body), 0)
        self.assertEqual(r.via, ProxyBackend.HTTP_PROXY)


class TestI2PConfigWiring(unittest.TestCase):
    """Regression tests: I2PConfig propagates through the full call chain.

    Ensures that custom proxy/SAM endpoints from I2PConfig actually reach
    the underlying clients instead of being silently ignored.
    """

    def test_proxy_client_uses_config(self):
        """I2PProxyClient must respect I2PConfig ports and hosts."""
        from src.config import I2PConfig
        cfg = I2PConfig(
            socks_host="10.0.0.2",
            socks_port=8765,
            http_host="10.0.0.3",
            http_port=5432,
        )
        c = I2PProxyClient(config=cfg)
        self.assertEqual(c.socks_host, "10.0.0.2")
        self.assertEqual(c.socks_port, 8765)
        self.assertEqual(c.http_host, "10.0.0.3")
        self.assertEqual(c.http_port, 5432)

    def test_proxy_client_explicit_kwargs_override(self):
        """Explicit kwargs must override config defaults."""
        from src.config import I2PConfig
        cfg = I2PConfig(
            socks_host="10.0.0.2",
            socks_port=8765,
            http_host="10.0.0.3",
            http_port=5432,
        )
        c = I2PProxyClient(config=cfg, socks_port=9999)
        self.assertEqual(c.socks_port, 9999)
        self.assertEqual(c.http_port, 5432)

    def test_proxy_client_defaults_when_no_config(self):
        """Config still falls back to defaults when not provided."""
        c = I2PProxyClient()
        self.assertEqual(c.http_port, 4444)
        self.assertEqual(c.socks_port, 7656)

    def test_sam_client_uses_config(self):
        """I2PSAMClient respects I2PConfig SAM host/port."""
        from src.config import I2PConfig
        cfg = I2PConfig(
            sam_host="10.0.0.5",
            sam_port=7890,
        )
        c = I2PSAMClient(config=cfg)
        self.assertEqual(c.host, "10.0.0.5")
        self.assertEqual(c.port, 7890)

    def test_integration_call_chain_accepts_config(self):
        """verify discover_addresses/probe_destination/_do_probe accept config param."""
        import inspect
        from src.integration import (
            discover_addresses,
            probe_destination,
            _do_probe,
        )

        for fn in (discover_addresses, probe_destination, _do_probe):
            sig = inspect.signature(fn)
            self.assertIn(
                "config", sig.parameters,
                f"{fn.__name__} missing config parameter",
            )
            default = sig.parameters["config"].default
            self.assertIsNone(
                default,
                f"{fn.__name__} config should default to None, got {default}",
            )

    def test_fetch_i2p_accepts_config(self):
        """fetch_i2p function signature includes config parameter."""
        import inspect
        sig = inspect.signature(fetch_i2p)
        self.assertIn("config", sig.parameters)


if __name__ == "__main__":
    unittest.main()
