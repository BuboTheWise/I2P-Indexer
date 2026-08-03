"""Tests for src/i2p_health.py — I2P network health detection."""
import re
import time
import unittest
from unittest.mock import MagicMock, patch

from src.i2p_health import (
    I2PHealth,
    _KB_RE,
    _parse_uptime,
    _parse_td_cells,
)


class TestI2PHealthDataclass(unittest.TestCase):
    """Test readiness scoring and status labels."""

    def test_ready_with_enough_peers_and_tunnels(self):
        health = I2PHealth(
            version="2.13.1-1",
            uptime_seconds=600,
            peers_connected=25,
            peers_target=53,
            client_tunnels_established=4,
            server_tunnels_running=8,
            bandwidth_in_kbps=2.0,
            bandwidth_out_kbps=3.0,
        )
        self.assertTrue(health.is_ready)
        self.assertEqual(health.status_label, "ready")

    def test_booting_with_no_peers(self):
        health = I2PHealth(uptime_seconds=30, peers_connected=0)
        self.assertFalse(health.is_ready)
        self.assertEqual(health.status_label, "down")

    def test_reconnecting_state(self):
        health = I2PHealth(
            uptime_seconds=200,
            peers_connected=5,
            peers_target=53,
            client_tunnels_established=2,
        )
        self.assertFalse(health.is_ready)  # too few peers
        self.assertIn(health.status_label, ("reconnecting", "booting"))

    def test_minimum_readiness(self):
        """8 peers and 2 client tunnels should be ready if uptime OK."""
        health = I2PHealth(
            uptime_seconds=300,
            peers_connected=8,
            peers_target=53,
            client_tunnels_established=2,
        )
        self.assertTrue(health.is_ready)

    def test_summary_contains_key_fields(self):
        health = I2PHealth(version="2.13.1-1", uptime_seconds=1800)
        text = health.summary()
        self.assertIn("2.13.1-1", text)
        self.assertIn("1800s", text)

    def test_readiness_score_range(self):
        health = I2PHealth(uptime_seconds=9999, peers_connected=999, peers_target=53)
        score = health.readiness_score
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)


class TestParseUptime(unittest.TestCase):
    """Test uptime string parsing."""

    def test_minutes_only(self):
        self.assertAlmostEqual(_parse_uptime("27 min"), 1620.0)

    def test_minutes_and_seconds(self):
        self.assertAlmostEqual(_parse_uptime("5 min 3 sec"), 303.0)

    def test_single_minute(self):
        self.assertAlmostEqual(_parse_uptime("1 min"), 60.0)

    def test_no_match_returns_zero(self):
        self.assertEqual(_parse_uptime(""), 0.0)
        self.assertEqual(_parse_uptime("just text"), 0.0)


class TestParseTdCells(unittest.TestCase):
    """Test HTML cell extraction."""

    def test_basic_cells(self):
        html = "<tr><td>Label</td><td align='right'>Value</td></tr>"
        cells = _parse_td_cells(html)
        self.assertEqual(cells, ["Label", "Value"])

    def test_nbsp_entity_handling(self):
        html = "<td>27&nbsp;min</td><td>1.5 / 2.0 KBps</td>"
        cells = _parse_td_cells(html)
        self.assertEqual(cells[0], "27 min")
        self.assertEqual(cells[1], "1.5 / 2.0 KBps")

    def test_nested_tags(self):
        html = "<td><a href='#'>Link text</a></td>"
        cells = _parse_td_cells(html)
        self.assertEqual(cells[0], "Link text")


class TestKBRegex(unittest.TestCase):
    """Test bandwidth/pair regex pattern."""

    def test_standard_format(self):
        m = _KB_RE.search("0.54 / 0.70")
        assert m is not None
        self.assertEqual(float(m.group(1)), 0.54)
        self.assertEqual(float(m.group(2)), 0.70)

    def test_integer_format(self):
        m = _KB_RE.search("12 / 284")
        assert m is not None
        self.assertEqual(int(m.group(1)), 12)
        self.assertEqual(int(m.group(2)), 284)


class TestFetchConsolePage(unittest.TestCase):
    """Test console page fetching with mocked HTTP."""

    def test_parse_peers_page(self):
        from src.i2p_health import _fetch_console_page

        fake_html = (
            "<tr><td>Version:</td><td align='right'>2.13.1-1</td></tr>"
            "<tr><td>Uptime:</td><td align='right'>30 min</td></tr>"
            "<tr><td>BW in/out:</td><td align='right'>2.0 / 3.0 KBps</td></tr>"
        )

        # opener.open(url).read() returns bytes directly (no context manager)
        mock_opener = MagicMock()
        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_html.encode("utf-8")
        mock_opener.open.return_value = mock_resp

        cells = _fetch_console_page(mock_opener, "/home")
        self.assertTrue(len(cells) >= 6)
        self.assertIn("2.13.1-1", cells)

    def test_connection_error_wrapped(self):
        from src.i2p_health import check_i2p_health
        import urllib.error

        with patch("src.i2p_health._fetch_console_page") as mock_fetch:
            mock_fetch.side_effect = urllib.error.URLError(
                "Connection refused"
            )
            with self.assertRaises(ConnectionError):
                check_i2p_health()


class TestWaitForReady(unittest.TestCase):
    """Test the polling helper."""

    def test_returns_on_ready(self):
        from src.i2p_health import wait_for_i2p_ready

        sample = I2PHealth(
            uptime_seconds=600,
            peers_connected=25,
            peers_target=53,
            client_tunnels_established=4,
        )
        self.assertTrue(sample.is_ready)

        with patch("src.i2p_health.check_i2p_health", return_value=sample):
            result = wait_for_i2p_ready(poll_interval=0.1)
        self.assertIsInstance(result, I2PHealth)

    def test_raises_timeout_on_unready(self):
        from src.i2p_health import wait_for_i2p_ready

        unready = I2PHealth(uptime_seconds=10, peers_connected=0)
        self.assertFalse(unready.is_ready)

        with patch("src.i2p_health.check_i2p_health", return_value=unready):
            with self.assertRaises(TimeoutError):
                wait_for_i2p_ready(timeout=0.5, poll_interval=0.1)


if __name__ == "__main__":
    unittest.main()
