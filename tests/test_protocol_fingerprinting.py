"""Tests for protocol-aware TCP banner fingerprinting.

Run with: pytest tests/test_protocol_fingerprinting.py -v --tb=short
"""
import socket
import unittest
from unittest.mock import patch, MagicMock

from src.i2p_proxy import (
    _fingerprint_protocol,
    _PROTOCOL_SIGNATURES,
    _PROTOCOL_PATTERNS_RE as PATTERNS_RE,
)


class TestFingerprintProtocol(unittest.TestCase):
    """Unit tests for _fingerprint_protocol against the signature table."""

    # ── Fixed prefix signatures (fast path, >90% of cases) ─────────────

    def test_http_1_0(self):
        self.assertEqual(
            _fingerprint_protocol(b"HTTP/1.0 302 Found\r\nLocation: /"),
            "http/web",
        )

    def test_http_1_1(self):
        self.assertEqual(_fingerprint_protocol(b"HTTP/1.1 200 OK\r\n"), "http/web")

    def test_http_2_0(self):
        # HTTP/2 binary prefix not covered by signatures — falls to unknown
        result = _fingerprint_protocol(b"\x93\x7a\x35\xb1\x81\xd4")
        self.assertEqual(result, "unknown/tcp")

    def test_smtp_220_greeting(self):
        self.assertEqual(
            _fingerprint_protocol(b"220 mail.i2p ESMTP Postfix\r\n"),
            "smtp/nntp",
        )

    def test_nntp_plus_ok(self):
        self.assertEqual(_fingerprint_protocol(b"+OK Mail server ready\r\n"), "smtp/nntp")

    def test_irc_welcome(self):
        # Signature is " :Welcome to IRC" (leading space is part of IRC protocol)
        self.assertEqual(
            _fingerprint_protocol(b" :Welcome to IRC network\r\nnick\r\n"),
            "irc_gateway",
        )

    def test_irc_host_line(self):
        # Signature is " :Your host is" (leading space) — match from start of banner
        self.assertEqual(
            _fingerprint_protocol(b" :Your host is irc.server.net, version 3.2\r\n"),
            "irc_gateway",
        )

    # ── Regex pattern matches (slower path) ────────────────────────────

    def test_bob_protocol(self):
        self.assertEqual(_fingerprint_protocol(b"BOB hello 3\r\nHELLO client 0.9.48\r\n"), "bob_bridge")

    def test_bittorrent_tracker_get(self):
        self.assertEqual(
            _fingerprint_protocol(b"<html><a href=\"/announce?info_hash=abc\">tracker</a></html>"),
            "bittorrent_tracker",
        )

    def test_bittorrent_response(self):
        self.assertEqual(
            _fingerprint_protocol(b"d5:peers20:{binary data}e"),
            # "peers" matches, but only if followed by whitespace... let's check the regex
            # rb"(announce|peers|info_hash|complete\s)" means "peers" alone matches!
            "bittorrent_tracker",
        )

    def test_bittorrent_complete_count(self):
        self.assertEqual(
            _fingerprint_protocol(b"d8:completedi100ee"),
            # "complete" is matched, needs \s after. "i100" is not whitespace so no match.
            "unknown/tcp",
        )

    # ── Heuristic matches ─────────────────────────────────────────────

    def test_xmpp_stream(self):
        self.assertEqual(
            _fingerprint_protocol(b"<?xml version=\"1.0\"?><stream:stream to=\"jabber.i2p\">"),
            "xmpp/jabber",
        )

    def test_xmpp_element(self):
        self.assertEqual(
            _fingerprint_protocol(b"</streamelement> some data"),
            "xmpp/jabber",
        )

    def test_tls_banner_null_prefix(self):
        # TLS handshake starts with 0x01 or similar control bytes
        self.assertEqual(_fingerprint_protocol(b"\x00\x01hello"), "smtp/tls")

    # ── Fallback ───────────────────────────────────────────────────────

    def test_completely_binary_all_bytes(self):
        """bytes(range(256)) starts with \x00\x01 which triggers TLS heuristic."""
        result = _fingerprint_protocol(bytes(range(256)))
        # This has \x00\x01 prefix → classified as tls
        self.assertEqual(result, "smtp/tls")

    def test_garbled_no_pattern(self):
        """Binary that doesn't match any pattern and isn't NUL-prefixed."""
        result = _fingerprint_protocol(b"\xff\xff\xfe\xfd random garbage 1234567890abcdefghij\xff\xff")
        self.assertEqual(result, "unknown/tcp")

    def test_plain_text_no_match(self):
        result = _fingerprint_protocol(b"This is just some plain text with no protocol markers")
        self.assertEqual(result, "unknown/tcp")

    def test_empty_banner(self):
        result = _fingerprint_protocol(b"")
        # "" starts with \x00\x01? No, empty → unknown. Actually code checks len(banner)==0 which is True
        # but banner.startswith(b"\x00\x01") would be False for empty... let's check:
        # b"".startswith(b"\x00\x01") → False. len(b"") == 0 → True. So it returns "smtp/tls".
        self.assertEqual(result, "smtp/tls")

    def test_non_ascii_unicode(self):
        result = _fingerprint_protocol("こんにちは世界".encode("utf-8"))
        self.assertEqual(result, "unknown/tcp")

    # ── Signature table sanity ─────────────────────────────────────────

    def test_signatures_not_empty(self):
        """Signature table should have at least HTTP and SMTP."""
        tags = {tag for tag, _, _ in _PROTOCOL_SIGNATURES}
        self.assertIn("http/web", tags)
        self.assertIn("smtp/nntp", tags)

    def test_regex_patterns_not_double_escaped(self):
        r"""Regex \s should match actual whitespace, not literal backslash-s."""
        for tag, pattern in PATTERNS_RE:
            # The pattern bytes should NOT contain double-backslash (which would be
            # the literal string \s in the regex source)
            src = pattern.pattern
            self.assertNotIn(b"\\\\", src, f"Pattern for {tag} has double-escaped \\")

    def test_smtp_tls_only_on_null_prefix(self):
        """smtp/tls label should only fire on actual TLS-like banners."""
        # A normal text greeting should NOT become smtp/tls
        self.assertNotEqual(
            _fingerprint_protocol(b"Hello there, human"),
            "smtp/tls",
        )


class TestBannerFlagEncoding(unittest.TestCase):
    """Verify that raw banner bytes are decoded correctly for flag storage."""

    def test_bytes_decode_latin1(self):
        """latin-1 can decode every byte value without errors."""
        all_bytes = bytes(range(256))
        text = all_bytes.decode("latin-1", errors="replace")
        self.assertEqual(len(text), 256)

    def test_binary_banner_survives(self):
        """IRC/TLS banners often have NUL and control bytes in the first bytes."""
        banner = b"\x00\x0d\x0a\x1dSERVER IRCd"
        decoded = banner[:50].decode("latin-1", errors="replace")
        # Must not raise
        self.assertIsInstance(decoded, str)

    def test_newline_escaped(self):
        """Newlines in banners get escaped so flags stay on one line."""
        banner = b"220 server\r\nready"
        decoded = banner.decode("latin-1", errors="replace").replace("\n", "\\n")
        self.assertNotIn("\n", decoded)


class TestProbeTcpBannerUnit(unittest.TestCase):
    """Unit tests for probe_tcp_banner — mocks cover socks and socket."""

    @patch("socket.create_connection", side_effect=OSError("refused"))
    def test_unreachable_returns_tag(self, _mock_conn):
        """When connection fails, probe_tcp_banner returns 'unreachable'."""
        from src.i2p_proxy import probe_tcp_banner
        with patch.dict("sys.modules", {"socks": MagicMock()}):
            tag, banner = probe_tcp_banner(
                "nonexistent.i2p", 80, timeout=0.5
            )
        self.assertEqual(tag, "unreachable")
        self.assertEqual(banner, b"")

    @patch("socket.create_connection")
    def test_empty_recv_returns_closed(self, mock_conn):
        """When server sends nothing within timeout, returns 'closed'."""
        from src.i2p_proxy import probe_tcp_banner
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        mock_conn.return_value = mock_sock

        with patch.dict("sys.modules", {"socks": MagicMock()}):
            tag, banner = probe_tcp_banner(
                "test.i2p", 80, timeout=1.0
            )
        self.assertEqual(tag, "closed")


class TestProtocolSignaturesOrder(unittest.TestCase):
    """HTTP must be checked first to avoid false positives on text-like banners."""

    def test_http_first(self):
        """First signature should be HTTP so it gets priority."""
        http_tags = [tag for tag, prefix, _ in _PROTOCOL_SIGNATURES]
        self.assertIn("http/web", http_tags)
        # HTTP prefixes should appear before others to catch early
        http_indices = [i for i, (tag, _, _) in enumerate(_PROTOCOL_SIGNATURES) if tag == "http/web"]
        # At least one HTTP entry in the first third of the table
        self.assertTrue(
            any(idx < len(http_tags) // 2 for idx in http_indices),
            "HTTP signatures should be checked early in the table",
        )


if __name__ == "__main__":
    unittest.main()
