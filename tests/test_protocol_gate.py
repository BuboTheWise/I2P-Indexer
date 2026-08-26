"""Tests for the protocol-gate subsystem.

Covers three layers:
  1. classify_service — pure banner→(protocol, confidence, label) mapping.
  2. ServiceClassification predicates — is_non_http / is_http / is_ambiguous.
  3. DiscoveryDB.record_service / get_service / get_services_by_host — the
     services table roundtrip and upsert semantics.
  4. probe_destination service_gate=True path — with probe_tcp_banner mocked,
     verify the gate fires for a confident non-HTTP banner and falls through
     for HTTP / ambiguous.

Run with:
    pytest tests/test_protocol_gate.py -v --tb=short

"""
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from src.i2p_proxy import (
    classify_service,
    ServiceClassification,
    _build_classification,
    _SERVICE_TYPE_LABELS,
    _HTTP_TAGS,
    _NON_HTTP_TAGS,
)
from src.integration import (
    DiscoveryDB,
    DiscoveryResult,
    probe_destination,
    _hex_to_b32_addr,
    GATE_CONFIDENCE_THRESHOLD,
)


# ---------------------------------------------------------------------------
# 1. classify_service — pure, no I/O
# ---------------------------------------------------------------------------

class TestClassifyService(unittest.TestCase):
    """classify_service is a pure function. No network, no time."""

    # HTTP banners → gate NOT applied, protocol=http/web.
    def test_http_1_1(self) -> None:
        r = classify_service(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n")
        self.assertEqual(r.protocol, "http/web")
        self.assertEqual(r.confidence, 1.00)
        self.assertTrue(r.is_http)
        self.assertFalse(r.is_non_http)
        self.assertIn(r.protocol, _HTTP_TAGS)

    def test_http_1_0(self) -> None:
        r = classify_service(b"HTTP/1.0 302 Found\r\n")
        self.assertEqual(r.protocol, "http/web")
        self.assertTrue(r.is_http)

    # SMTP / NNTP
    def test_smtp_220(self) -> None:
        r = classify_service(b"220 mail.i2p ESMTP Postfix\r\n")
        self.assertEqual(r.protocol, "smtp/nntp")
        self.assertFalse(r.is_http)
        self.assertTrue(r.is_non_http,
                        f"SMTP with exact prefix should gate; got conf={r.confidence}")
        self.assertEqual(r.service_type, "Mail/NNTP")
        self.assertEqual(r.confidence, 1.00)

    def test_nntp_plus_ok(self) -> None:
        r = classify_service(b"+OK Mail server ready\r\n")
        self.assertEqual(r.protocol, "smtp/nntp")
        self.assertTrue(r.is_non_http)

    # IRC
    def test_irc_welcome(self) -> None:
        banner = b" :Welcome to IRC gateway at irc.i2p\r\n"
        r = classify_service(banner)
        self.assertEqual(r.protocol, "irc_gateway")
        self.assertEqual(r.service_type, "I2P IRC gateway")
        self.assertTrue(r.is_non_http)
        self.assertAlmostEqual(r.confidence, 1.00)

    def test_irc_host_line(self) -> None:
        r = classify_service(b" :Your host is irc.example.i2p, 3.2")
        self.assertEqual(r.protocol, "irc_gateway")
        self.assertTrue(r.is_non_http)

    # BOB
    def test_bob(self) -> None:
        r = classify_service(b"BOB 1.0 (I2P bridge)")
        self.assertEqual(r.protocol, "bob_bridge")
        self.assertTrue(r.is_non_http)

    # Bittorrent (regex path, confidence 0.90)
    def test_bittorrent_announce(self) -> None:
        r = classify_service(b"::announce?info_hash=abc123&peer=xyz")
        self.assertEqual(r.protocol, "bittorrent_tracker")
        self.assertTrue(r.is_non_http)
        self.assertAlmostEqual(r.confidence, 0.90)
        self.assertEqual(r.service_type, "Bittorrent peer/tracker")

    # Unknown / empty — low confidence, no gate.
    def test_empty_banner(self) -> None:
        r = classify_service(b"")
        self.assertFalse(r.is_non_http)
        self.assertLess(r.confidence, GATE_CONFIDENCE_THRESHOLD)

    def test_binary_junk(self) -> None:
        # 10 bytes of binary — nothing we recognize.
        banner = bytes(range(10))
        r = classify_service(banner)
        self.assertFalse(r.is_non_http)
        self.assertLess(r.confidence, GATE_CONFIDENCE_THRESHOLD)


class TestServiceClassificationPredicates(unittest.TestCase):
    """is_non_http is the only gate predicate; it is asymmetric."""

    def test_gate_requires_confidence_threshold(self) -> None:
        high = ServiceClassification(
            protocol="irc_gateway", confidence=GATE_CONFIDENCE_THRESHOLD,
            raw_banner=b" :Welcome", service_type="x",
        )
        low = ServiceClassification(
            protocol="irc_gateway", confidence=GATE_CONFIDENCE_THRESHOLD - 0.01,
            raw_banner=b" :Welcome", service_type="x",
        )
        self.assertTrue(high.is_non_http)
        self.assertFalse(low.is_non_http)

    def test_http_never_gates(self) -> None:
        # Even a confidence-1.0 HTTP banner is not "non-HTTP".
        h = ServiceClassification(
            protocol="http/web", confidence=1.00, raw_banner=b"", service_type="",
        )
        self.assertFalse(h.is_non_http)
        self.assertTrue(h.is_http)

    def test_label_lookup_is_total(self) -> None:
        # Every tag known to the tables has a display label (or defaults to itself).
        for tag in _HTTP_TAGS | _NON_HTTP_TAGS:
            self.assertIn(tag, _SERVICE_TYPE_LABELS, f"missing label for {tag}")


# ---------------------------------------------------------------------------
# 3. DiscoveryDB services table
# ---------------------------------------------------------------------------

class TestServicesTable(unittest.TestCase):
    """record_service upserts by (host, port) and is queryable."""

    def setUp(self) -> None:
        self.tmp = tempfile.mktemp(suffix=".db")
        self.db = DiscoveryDB(self.tmp)

    def tearDown(self) -> None:
        self.db.close()
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def test_first_insert(self) -> None:
        ok = self.db.record_service(
            host="irc.i2p", port=6667, protocol="irc_gateway",
            service_type="I2P IRC gateway", banner=b" :Welcome to IRC",
        )
        self.assertTrue(ok)
        rows = self.db._conn.execute(
            "SELECT host, port, protocol, service_type, status FROM services"
        ).fetchall()
        self.assertEqual(len(rows), 1)
        host, port, proto, stype, status = rows[0]
        self.assertEqual(host, "irc.i2p")
        self.assertEqual(port, 6667)
        self.assertEqual(proto, "irc_gateway")
        self.assertEqual(stype, "I2P IRC gateway")
        self.assertEqual(status, "ok")

    def test_upsert_updates_same_row(self) -> None:
        self.db.record_service(
            host="irc.i2p", port=6667, protocol="irc_gateway",
            service_type="I2P IRC gateway", banner=b" :Welcome v1",
        )
        # Re-record with a changed banner — same (host, port) → UPDATE, not INSERT.
        self.db.record_service(
            host="irc.i2p", port=6667, protocol="irc_gateway",
            service_type="I2P IRC gateway", banner=b" :Welcome v2",
        )
        rows = self.db._conn.execute("SELECT * FROM services").fetchall()
        self.assertEqual(len(rows), 1, "upsert should not create a new row")
        cur = self.db._conn.execute(
            "SELECT banner_hash, banner_text FROM services WHERE host='irc.i2p'"
        ).fetchone()
        self.assertEqual(cur[1], " :Welcome v2")

    def test_banner_text_is_ascii_printable(self) -> None:
        # Mixed binary + ASCII — decode should ignore non-ASCII bytes.
        banner = b" :Welcome \x00\x01\x02\x03 to IRC"
        self.db.record_service(
            host="x.i2p", port=1, protocol="irc_gateway",
            service_type="IRC", banner=banner,
        )
        text = self.db._conn.execute(
            "SELECT banner_text FROM services WHERE host='x.i2p'"
        ).fetchone()[0]
        self.assertIn("Welcome", text)
        self.assertIn("IRC", text)

    def test_different_ports_are_separate_rows(self) -> None:
        self.db.record_service(
            host="multi.i2p", port=443, protocol="http/web",
            service_type="web", banner=b"HTTP/1.1 200 OK",
        )
        self.db.record_service(
            host="multi.i2p", port=6667, protocol="irc_gateway",
            service_type="IRC", banner=b" :Welcome",
        )
        count = self.db._conn.execute(
            "SELECT COUNT(*) FROM services WHERE host='multi.i2p'"
        ).fetchone()[0]
        self.assertEqual(count, 2)


# ---------------------------------------------------------------------------
# DiscoveryResult gate fields
# ---------------------------------------------------------------------------

class TestDiscoveryResultGateFields(unittest.TestCase):

    def test_default_gate_state(self) -> None:
        r = DiscoveryResult()
        self.assertFalse(r.gate_applied)
        self.assertEqual(r.gate_confidence, 0.0)
        self.assertEqual(r.service_type, "")
        self.assertEqual(r.service_protocol, "")

    def test_populated_gate(self) -> None:
        r = DiscoveryResult(
            reachable=True,
            service_type="I2P IRC gateway",
            service_protocol="irc_gateway",
            gate_applied=True,
            gate_confidence=0.95,
        )
        self.assertTrue(r.gate_applied)
        self.assertEqual(r.gate_confidence, 0.95)


# ---------------------------------------------------------------------------
# probe_destination gate path — with probe_tcp_banner mocked
# ---------------------------------------------------------------------------

class TestProbeDestinationGate(unittest.TestCase):
    """Verify the gate fires for non-HTTP and falls through for HTTP."""

    def setUp(self) -> None:
        self.tmp = tempfile.mktemp(suffix=".db")
        self.db = DiscoveryDB(self.tmp)
        # A fake 40-hex ident hash → b32 addr.
        self.hash = "a" * 40
        # We'll patch probe_tcp_banner inside src.integration.
        self.banner_patch = patch(
            "src.i2p_proxy.probe_tcp_banner",  # resolved via src.i2p_proxy
        )

    def tearDown(self) -> None:
        self.db.close()
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def _mock_banner(self, banner: bytes, tag: str):
        """Return a MagicMock for src.i2p_proxy.probe_tcp_banner."""
        m = MagicMock()
        m.return_value = (tag, banner)
        return m

    def test_gate_fires_for_confident_non_http(self) -> None:
        banner = b" :Welcome to IRC at irc.i2p\r\n"
        mock = self._mock_banner(banner, "irc_gateway")
        with patch("src.integration.probe_tcp_banner", mock), \
              patch("src.integration.classify_service", lambda b: classify_service(b)):
            res = probe_destination(
                self.hash, db=self.db, timeout=5,
                service_gate=True,
            )
        self.assertTrue(res.reachable)
        self.assertTrue(res.gate_applied)
        self.assertEqual(res.service_protocol, "irc_gateway")
        self.assertEqual(res.service_type, "I2P IRC gateway")
        self.assertGreater(res.gate_confidence, 0.85)
        self.assertIn(res.via_method, ("banner_gate",))
        # The services table must have a row.
        rows = self.db._conn.execute("SELECT * FROM services").fetchall()
        self.assertGreaterEqual(len(rows), 1)

    def test_gate_falls_through_for_http_banner(self) -> None:
        banner = b"HTTP/1.1 200 OK\r\n"
        mock = self._mock_banner(banner, "http/web")
        # The HTTP path needs a stub for fetch — we just want to confirm the
        # gate did NOT fire (via_method should be "b32", not "banner_gate").
        with patch("src.i2p_proxy.probe_tcp_banner", mock):
            res = probe_destination(
                self.hash, db=self.db, timeout=1,
                service_gate=True,
            )
        # On the HTTP fall-through path, the b32 probe runs.  Its fetch will
        # fail (no real I2P) but the result's gate_applied must be False.
        self.assertFalse(res.gate_applied,
                         f"HTTP banner must not gate; res.via_method={res.via_method}")

    def test_gate_off_behaves_as_before(self) -> None:
        mock = self._mock_banner(b" :Welcome", "irc_gateway")
        with patch("src.i2p_proxy.probe_tcp_banner", mock):
            res = probe_destination(
                self.hash, db=self.db, timeout=1,
                service_gate=False,
            )
        # Gate off → probe_tcp_banner must NOT have been called.
        self.assertFalse(res.gate_applied)
        mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
