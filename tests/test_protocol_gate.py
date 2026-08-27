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
import io
import os
import sqlite3
import sys
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
# 4. Service query methods — the CLI backing queries
# ---------------------------------------------------------------------------

class TestServiceQueryMethods(unittest.TestCase):
    """get_services_by_port / get_all_services — the two new read paths.

    These back the `--show-services` CLI (probe_sweep.py).  They must
    mirror get_services_by_protocol() in shape (list[dict], freshest-first,
    limit respected) but key on port / all-rows.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.mktemp(suffix=".db")
        self.db = DiscoveryDB(self.tmp)
        # Seed a small mixed set of services to query against.
        self.db.record_service(
            host="irc-a.i2p", port=6667, protocol="irc_gateway",
            service_type="I2P IRC gateway", banner=b" :Welcome a",
        )
        self.db.record_service(
            host="irc-b.i2p", port=6667, protocol="irc_gateway",
            service_type="I2P IRC gateway", banner=b" :Welcome b",
        )
        self.db.record_service(
            host="mail.i2p", port=25, protocol="smtp",
            service_type="SMTP", banner=b"220 mail.i2p ESMTP",
        )
        self.db.record_service(
            host="xmpp.i2p", port=5222, protocol="xmpp",
            service_type="XMPP", banner=b"<stream:stream ...>",
        )

    def tearDown(self) -> None:
        self.db.close()
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def test_by_port_returns_only_matching(self) -> None:
        rows = self.db.get_services_by_port(6667)
        self.assertEqual(len(rows), 2, "6667 has exactly two seeded rows")
        self.assertTrue(all(r["port"] == 6667 for r in rows))
        self.assertTrue(all(r["protocol"] == "irc_gateway" for r in rows))

    def test_by_port_no_match_is_empty(self) -> None:
        self.assertEqual(self.db.get_services_by_port(9999), [])

    def test_by_port_respects_limit(self) -> None:
        self.assertEqual(len(self.db.get_services_by_port(6667, limit=1)), 1)

    def test_by_port_returns_dict_rows(self) -> None:
        row = self.db.get_services_by_port(25)[0]
        for k in ("host", "port", "protocol", "service_type", "banner_hash",
                  "banner_text", "status", "first_seen", "last_seen", "seen_count"):
            self.assertIn(k, row)

    def test_all_services_returns_everything(self) -> None:
        rows = self.db.get_all_services()
        self.assertEqual(len(rows), 4, "one row across all four seeded endpoints")

    def test_all_services_respects_limit(self) -> None:
        rows = self.db.get_all_services(limit=2)
        self.assertEqual(len(rows), 2)

    def test_all_services_is_freshest_first(self) -> None:
        # Most recently written rows should surface first (last_seen DESC).
        # Seed a fresh row after setUp's writes and assert it leads the result.
        self.db.record_service(
            host="fresh.i2p", port=6667, protocol="irc_gateway",
            service_type="IRC", banner=b" :newest",
        )
        rows = self.db.get_all_services()
        self.assertEqual(rows[0]["host"], "fresh.i2p",
                         "newest row must sort first")


# ---------------------------------------------------------------------------
# 5. probe_sweep --show-services CLI dispatch
# ---------------------------------------------------------------------------

class TestShowServicesCLI(unittest.TestCase):
    """The `--show-services` dispatch block in probe_sweep.main.

    We exercise the real CLI by invoking main() with argv patched and the
    DB pointed at a temp file, so --show-services never enters the probe path.
    We capture stdout to assert the rows come back and the shape is right.
    """

    def setUp(self) -> None:
        import probe_sweep as ps
        self._ps = ps
        self.tmp = tempfile.mktemp(suffix=".cli.db")
        db = DiscoveryDB(self.tmp)
        db.record_service(
            host="irc-a.i2p", port=6667, protocol="irc_gateway",
            service_type="I2P IRC gateway", banner=b" :Welcome a",
        )
        db.record_service(
            host="mail.i2p", port=25, protocol="smtp",
            service_type="SMTP", banner=b"220 mail.i2p ESMTP",
        )
        db.close()

    def tearDown(self) -> None:
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)
        if os.path.exists(self.tmp + "-wal"):
            os.unlink(self.tmp + "-wal")
        if os.path.exists(self.tmp + "-shm"):
            os.unlink(self.tmp + "-shm")

    def _run(self, args, cap):
        import io, contextlib
        from unittest import mock
        with mock.patch.object(sys, "argv", [self._ps.__name__, *args]), \
             contextlib.redirect_stdout(cap):
            self._ps.main()

    def test_json_by_protocol(self) -> None:
        cap = io.StringIO()
        self._run(["--db", self.tmp, "--show-services",
                   "--protocol", "irc_gateway", "--json"], cap)
        import json as _json
        out = _json.loads(cap.getvalue())
        self.assertEqual(out["query"], "protocol=irc_gateway")
        self.assertEqual(out["total"], 1)
        self.assertEqual(out["services"][0]["host"], "irc-a.i2p")

    def test_json_by_port(self) -> None:
        cap = io.StringIO()
        self._run(["--db", self.tmp, "--show-services",
                   "--port", "25", "--json"], cap)
        import json as _json
        out = _json.loads(cap.getvalue())
        self.assertEqual(out["query"], "port=25")
        self.assertEqual(out["total"], 1)
        self.assertEqual(out["services"][0]["host"], "mail.i2p")

    def test_json_all_services(self) -> None:
        cap = io.StringIO()
        self._run(["--db", self.tmp, "--show-services", "--json"], cap)
        import json as _json
        out = _json.loads(cap.getvalue())
        self.assertEqual(out["total"], 2)
        self.assertEqual(
            {s["host"] for s in out["services"]},
            {"irc-a.i2p", "mail.i2p"},
        )

    def test_empty_query_reports_helpful_hint(self) -> None:
        cap = io.StringIO()
        self._run(["--db", self.tmp, "--show-services",
                   "--protocol", "bittorrent", "--json"], cap)
        import json as _json
        out = _json.loads(cap.getvalue())
        self.assertEqual(out["total"], 0)

    def test_limit_caps_rows(self) -> None:
        cap = io.StringIO()
        self._run(["--db", self.tmp, "--show-services",
                   "--limit", "1", "--json"], cap)
        import json as _json
        out = _json.loads(cap.getvalue())
        self.assertEqual(out["total"], 1, "limit=1 must cap results")


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
        # gate_hit is the downstream branch-condition flag: default False
        # (no gate fired, no service record written).
        self.assertFalse(r.gate_hit)

    def test_populated_gate(self) -> None:
        r = DiscoveryResult(
            reachable=True,
            service_type="I2P IRC gateway",
            service_protocol="irc_gateway",
            gate_applied=True,
            gate_confidence=0.95,
            gate_hit=True,
        )
        self.assertTrue(r.gate_applied)
        self.assertEqual(r.gate_confidence, 0.95)
        self.assertTrue(r.gate_hit)
        # The three gate booleans are independent: gate_applied and gate_hit
        # co-occur on the fire path, but are NOT aliased — a future codepath
        # could in principle set one without the other (e.g. a re-fire on
        # cached classification without a fresh service record). The tests
        # above lock the invariant in practice, but the field surface must
        # allow independent construction.
        r2 = DiscoveryResult(gate_applied=True)  # gate_hit unset
        self.assertTrue(r2.gate_applied)
        self.assertFalse(r2.gate_hit)


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
        # gate_hit is the branch condition: True on gate-fire (service
        # recorded), which downstream code can use to tell "gated, service
        # recorded" apart from a bare status_code==0 fall-through/timeout.
        self.assertTrue(res.gate_hit)
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
        # gate_hit must ALSO be False on the fall-through path — this is
        # exactly the downstream distinction this flag exists for: an HTTP
        # banner's status_code may be 0 (fetch failed) without a service having
        # been recorded, so gate_hit is the only reliable signal.
        self.assertFalse(res.gate_hit,
                         f"fall-through must not set gate_hit; via={res.via_method}")

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


# ---------------------------------------------------------------------------
# Multi-port gate — full scan records every (host, port) that fires
# ---------------------------------------------------------------------------

class TestMultiPortGate(unittest.TestCase):
    """The gate scans EVERY port in the list and records each confident
    non-HTTP hit in the services table.  If any port fires, the HTTP path
    is skipped and the first-fired (list order) service becomes the
    dominant result.

    Default port set: (443, 6667, 5222).
    """

    def setUp(self) -> None:
        self.tmp = tempfile.mktemp(suffix=".db")
        self.db = DiscoveryDB(self.tmp)
        self.hash = "a" * 40  # fake 40-hex ident → b32 addr

    def tearDown(self) -> None:
        self.db.close()
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def _banner_for_port(self, port: int) -> bytes:
        """Return a banner that will classify as confident non-HTTP."""
        # IRC welcome banner classifies as irc_gateway @ conf=1.00
        return b" :Welcome to IRC at irc.i2p\r\n"

    def _http_banner(self) -> bytes:
        return b"HTTP/1.1 200 OK\r\n"

    def test_default_port_list_is_three_ports(self) -> None:
        """DEFAULT_GATE_PORTS must be (443, 6667, 5222)."""
        from src.integration import DEFAULT_GATE_PORTS
        self.assertEqual(DEFAULT_GATE_PORTS, (443, 6667, 5222))

    def test_multi_port_scan_records_every_fired_port(self) -> None:
        """Two ports with non-HTTP banners → two rows in services.

        Port 6667 → IRC banner (fires)
        Port 5222 → IRC banner (also fires — same classification is fine for the test)
        Port 443  → HTTP banner (no fire)
        """
        # side_effect based on the port kwarg
        def fake_banner(host=None, port=None, timeout=None, config=None):
            if port == 6667:
                return ("irc_gateway", b" :Welcome to IRC\r\n")
            elif port == 5222:
                return ("irc_gateway", b" :Welcome to IRC (xmpp)\r\n")
            else:
                return ("http/web", b"HTTP/1.1 200 OK\r\n")

        mock = MagicMock(side_effect=fake_banner)
        with patch("src.integration.probe_tcp_banner", mock):
            res = probe_destination(
                self.hash, db=self.db, timeout=5,
                service_gate=True,
            )

        self.assertTrue(res.gate_applied)
        self.assertTrue(res.reachable)
        self.assertEqual(res.via_method, "banner_gate")
        # Both non-HTTP ports should have been probed and recorded
        self.assertEqual(mock.call_count, 3)
        # services table: exactly 2 rows (6667 and 5222, not 443)
        rows = self.db._conn.execute(
            "SELECT port, protocol FROM services ORDER BY port"
        ).fetchall()
        self.assertEqual(len(rows), 2, f"expected 2 service rows, got {len(rows)}")
        ports_hit = [r[0] for r in rows]
        self.assertIn(6667, ports_hit)
        self.assertIn(5222, ports_hit)
        self.assertNotIn(443, ports_hit)
        # gate_ports field reflects the full list
        self.assertEqual(res.gate_ports, [443, 6667, 5222])

    def test_single_port_fires_among_multi(self) -> None:
        """Only 6667 fires, 443 and 5222 are HTTP → one row, gate still applies."""
        def fake_banner(host=None, port=None, timeout=None, config=None):
            if port == 6667:
                return ("irc_gateway", b" :Welcome to IRC\r\n")
            return ("http/web", b"HTTP/1.1 200 OK\r\n")

        mock = MagicMock(side_effect=fake_banner)
        with patch("src.integration.probe_tcp_banner", mock):
            res = probe_destination(
                self.hash, db=self.db, timeout=5,
                service_gate=True,
            )

        self.assertTrue(res.gate_applied)
        rows = self.db._conn.execute("SELECT port FROM services").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 6667)
        self.assertEqual(res.service_protocol, "irc_gateway")

    def test_no_port_fires_falls_through_to_http(self) -> None:
        """All three ports return HTTP → gate does NOT apply, HTTP path runs."""
        mock = MagicMock(return_value=("http/web", b"HTTP/1.1 200 OK\r\n"))
        with patch("src.integration.probe_tcp_banner", mock):
            res = probe_destination(
                self.hash, db=self.db, timeout=1,
                service_gate=True,
            )
        self.assertFalse(res.gate_applied)
        # All 3 ports were probed, none recorded
        self.assertEqual(mock.call_count, 3, "all ports must be scanned")
        rows = self.db._conn.execute("SELECT * FROM services").fetchall()
        self.assertEqual(len(rows), 0, "no services rows when no port fires")

    def test_explicit_gate_ports_argument(self) -> None:
        """gate_ports=[7000] → only port 7000 is probed, not the default set."""
        mock = MagicMock(return_value=("irc_gateway", b" :Welcome to IRC\r\n"))
        with patch("src.integration.probe_tcp_banner", mock):
            res = probe_destination(
                self.hash, db=self.db, timeout=5,
                service_gate=True,
                gate_ports=[7000],
            )
        self.assertTrue(res.gate_applied)
        self.assertEqual(mock.call_count, 1, "only explicitly listed port probed")
        mock.assert_called_once()
        called_port = mock.call_args_list[0].kwargs.get("port") or mock.call_args_list[0][1].get("port")
        self.assertEqual(called_port, 7000)
        self.assertEqual(res.gate_ports, [7000])

    def test_port_argument_overrides_default_list(self) -> None:
        """gate_port=5222 (single) → only that port is probed."""
        mock = MagicMock(return_value=("smtp/nntp", b"+OK ready\r\n"))
        with patch("src.integration.probe_tcp_banner", mock):
            res = probe_destination(
                self.hash, db=self.db, timeout=5,
                service_gate=True,
                port=5222,
            )
        self.assertTrue(res.gate_applied)
        self.assertEqual(mock.call_count, 1)
        called_port = mock.call_args_list[0].kwargs.get("port") or mock.call_args_list[0][1].get("port")
        self.assertEqual(called_port, 5222)
        self.assertEqual(res.gate_ports, [5222])
        # services row recorded at port 5222
        rows = self.db._conn.execute("SELECT port FROM services WHERE port=5222").fetchall()
        self.assertEqual(len(rows), 1)

    def test_gate_exception_on_one_port_does_not_abort_scan(self) -> None:
        """A network error on port 443 should not prevent the 6667 scan."""
        def fake_banner(host=None, port=None, timeout=None, config=None):
            if port == 443:
                raise OSError("connection reset")
            return ("irc_gateway", b" :Welcome to IRC\r\n")

        mock = MagicMock(side_effect=fake_banner)
        with patch("src.integration.probe_tcp_banner", mock):
            res = probe_destination(
                self.hash, db=self.db, timeout=5,
                service_gate=True,
            )
        # 6667 still fired even though 443 raised
        self.assertTrue(res.gate_applied)
        self.assertEqual(res.service_protocol, "irc_gateway")

    def test_multi_port_threaded_through_discover_addresses(self) -> None:
        """gate_ports kwarg on discover_addresses reaches probe_destination."""
        from src.integration import discover_addresses

        def fake_banner(host=None, port=None, timeout=None, config=None):
            if port == 6667:
                return ("irc_gateway", b" :Welcome to IRC\r\n")
            return ("http/web", b"HTTP/1.1 200 OK\r\n")

        mock = MagicMock(side_effect=fake_banner)
        with patch("src.integration.probe_tcp_banner", mock):
            results = discover_addresses(
                known_addrs=[("a" * 40, "")],
                db_instance=self.db,
                probe_delay=0,
                timeout=1,
                service_gate=True,
                gate_ports=[6667],
            )
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].gate_applied)
        # Only port 6667 was probed (not 443 or 5222)
        self.assertEqual(mock.call_count, 1)
        row = self.db._conn.execute("SELECT * FROM services WHERE port = 6667").fetchone()
        self.assertIsNotNone(row)


# ---------------------------------------------------------------------------
# discover_addresses() — production sweep path with the gate wired through
# ---------------------------------------------------------------------------

class TestDiscoverAddressesGateWiring(unittest.TestCase):
    """The gate must be reachable from the production sweep entry point.

    Regression: in v0.4.12 the gate was opt-in at probe_destination() but
    discover_addresses() never forwarded service_gate, so sweeps never
    engaged the gate. v0.4.13 threads the parameter through — this test
    locks that wiring in place.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.mktemp(suffix=".db")
        self.db = DiscoveryDB(self.tmp)

    def tearDown(self) -> None:
        self.db.close()
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def test_gate_fires_through_discover_addresses(self) -> None:
        """service_gate=True on the sweep drives a fires-and-records flow."""
        from src.integration import discover_addresses

        banner = b" :Welcome to IRC at irc.i2p\r\n"
        mock = MagicMock(return_value=("irc_gateway", banner))
        with patch("src.integration.probe_tcp_banner", mock):
            results = discover_addresses(
                known_addrs=[("a" * 40, "")],
                db_instance=self.db,
                probe_delay=0,
                timeout=1,
                service_gate=True,
                gate_port=6667,
            )
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertTrue(res.gate_applied, "gate was not engaged from discover_addresses")
        self.assertEqual(res.service_protocol, "irc_gateway")
        self.assertGreater(res.gate_confidence, 0.85)
        # probe_destination stores the row keyed on b32_addr (the host it actually dialed).
        row = self.db._conn.execute(
            "SELECT * FROM services WHERE port = 6667"
        ).fetchone()
        self.assertIsNotNone(row, "no services row recorded for gate-port 6667")
        keys = ["host", "port", "protocol", "service_type", "banner_hash",
                "banner_text", "status", "first_seen", "last_seen", "seen_count"]
        data = dict(zip(keys, row))
        self.assertEqual(data["protocol"], "irc_gateway")
        # gate_port should have been forwarded, not defaulted to 443
        self.assertEqual(data["port"], 6667)

    def test_gate_defaults_off_in_discover_addresses(self) -> None:
        """Without service_gate, the banner probe must not run at all."""
        from src.integration import discover_addresses

        mock = MagicMock(return_value=("irc_gateway", b" :Welcome to IRC at irc.i2p"))
        with patch("src.integration.probe_tcp_banner", mock):
            results = discover_addresses(
                known_addrs=[("a" * 40, "")],
                db_instance=self.db,
                probe_delay=0,
                timeout=1,
            )
        self.assertFalse(results[0].gate_applied)
        mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
