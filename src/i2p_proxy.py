"""I2P proxy client — SOCKS5 and SAM API interfaces.

Provides two ways to talk to the I2P darknet through a local daemon:

  - Approach A (SOCKS5): route HTTP requests via the daemon's SOCKS5 proxy.
    Uses ``socks`` (PySocks) module monkey-patched with the standard
    library socket + urllib, or httpx when available.

  - Approach B (SAM v3.x): open an explicit client tunnel through the
    Simple API Machine protocol over a plain TCP connection to the daemon.

Unified helper: ``fetch_i2p(url, via=…)`` routes through whichever backend
you choose and returns a consistent ``Response`` wrapper.

Working example (SOCKS5 proxy on port 7656):

    >>> from src.i2p_proxy import fetch_i2p
    >>> r = fetch_i2p("http://i2pstat.i2p/", via="http-proxy")
    >>> print(r.status)           # 200, 4xx, 502 depending on eepsite
    >>> print(len(r.body))        # bytes actually received
"""

from __future__ import annotations

import http.client as http_client
import logging
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .config import I2PConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class ProxyBackend(Enum):
    SOCKS5 = "socks5"
    HTTP_PROXY = "http-proxy"
    SAM = "sam"


@dataclass
class Response:
    """Thin wrapper around an I2P fetch result."""

    url: str
    status: int
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    encoding: str = "utf-8"
    elapsed: float = 0.0
    via: ProxyBackend = ProxyBackend.HTTP_PROXY

    @property
    def text(self) -> str:
        try:
            return self.body.decode(self.encoding, errors="replace")
        except Exception:
            return self.body.decode("utf-8", errors="replace")

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def title(self) -> Optional[str]:
        """Extract <title> from HTML body (best-effort)."""
        try:
            m = re.search(
                r"<title[^>]*>(.*?)</title>",
                self.text[:8000],
                re.IGNORECASE | re.DOTALL,
            )
            return m.group(1).strip() if m else None
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Approach A — SOCKS5 / HTTP Proxy client
# ---------------------------------------------------------------------------

class I2PProxyClient:
    """Route HTTP requests through a local I2P daemon's proxy interfaces.

    Parameters
    ----------
    config: optional ``I2PConfig`` with proxy endpoints.  When omitted,
            a default ``I2PConfig()`` is created (127.0.0.1, standard ports).
    socks_host, socks_port: explicit override for the SOCKS5 proxy address.
    http_host, http_port: explicit override for the HTTP CONNECT proxy.
    timeout: seconds before we give up on individual requests.

    Example — SOCKS5 via PySocks + standard urllib:

        client = I2PProxyClient()
        r = client.request("http://i2pstat.i2p/", backend="socks5")
    """

    def __init__(
        self,
        config: Optional[I2PConfig] = None,
        socks_host: Optional[str] = None,
        socks_port: Optional[int] = None,
        http_host: Optional[str] = None,
        http_port: Optional[int] = None,
        timeout: float = 120.0,
    ):
        cfg = config or I2PConfig()
        self.socks_host = socks_host if socks_host is not None else cfg.socks_host
        self.socks_port = socks_port if socks_port is not None else cfg.socks_port
        self.http_host = http_host if http_host is not None else cfg.http_host
        self.http_port = http_port if http_port is not None else cfg.http_port
        self.timeout = timeout

    # -- SOCKS5 via PySocks -------------------------------------------------

    def _socks_request(self, url: str) -> Response:
        """Fetch *url* by monkey-patching socket with PySocks."""
        import socks

        _start = time.monotonic()
        original_socket = socket.socket
        try:
            # Monkey-patch socket for the duration of this request
            socks.set_default_proxy(
                socks.PROXY_TYPE_SOCKS5, self.socks_host, self.socks_port
            )
            socket.socket = socks.socksocket

            req = urllib.request.Request(url)
            req.add_header("User-Agent", "I2PIndexer/0.1")
            resp = urllib.request.urlopen(req, timeout=self.timeout)

            body = resp.read()
            status = resp.getcode()
            headers = dict(resp.getheaders()) if hasattr(resp, "getheaders") else {}
            resp.close()

            elapsed = time.monotonic() - _start
            return Response(
                url=url,
                status=status,
                headers=headers,
                body=body,
                elapsed=round(elapsed, 2),
                via=ProxyBackend.SOCKS5,
            )
        except Exception as e:
            elapsed = time.monotonic() - _start
            logger.warning("SOCKS5 request to %s failed: %s", url, e)
            return Response(
                url=url,
                status=0,
                body=b"",
                elapsed=round(elapsed, 2),
                via=ProxyBackend.SOCKS5,
            )
        finally:
            socket.socket = original_socket

    # -- HTTP CONNECT proxy -------------------------------------------------

    def _http_proxy_request(self, url: str) -> Response:
        """Fetch *url* through the daemon's HTTP CONNECT proxy.
        
        Uses urllib with a ProxyHandler — this works reliably with the Java I2P
        daemon's HTTP proxy which handles full requests (not just raw tunnels).
        """
        _start = time.monotonic()

        try:
            proxy_handler = urllib.request.ProxyHandler(
                {"http": f"http://{self.http_host}:{self.http_port}"}
            )
            opener = urllib.request.build_opener(proxy_handler)

            req = urllib.request.Request(url)
            req.add_header("User-Agent", "I2PIndexer/0.1")

            resp = opener.open(req, timeout=int(self.timeout))
            body = resp.read()
            status = resp.getcode()
            headers = dict(resp.getheaders()) if hasattr(resp, "getheaders") else {}
            resp.close()

            elapsed = time.monotonic() - _start
            logger.info(
                "HTTP proxy -> %s: status=%d, bytes=%d, time=%.1fs",
                url, status, len(body), elapsed,
            )
            return Response(
                url=url,
                status=status,
                headers=headers,
                body=body,
                elapsed=round(elapsed, 2),
                via=ProxyBackend.HTTP_PROXY,
            )
        except Exception as e:
            elapsed = time.monotonic() - _start
            logger.warning("HTTP proxy request to %s failed (%.1fs): %s", url, elapsed, e)
            return Response(
                url=url,
                status=0,
                body=b"",
                elapsed=round(elapsed, 2),
                via=ProxyBackend.HTTP_PROXY,
            )

    # -- Public API ---------------------------------------------------------

    def request(self, url: str, backend: str = "http-proxy") -> Response:
        """Fetch *url* through whichever proxy backend you specify.

        Parameters
        ----------
        url: full URL (e.g., ``http://i2pstat.i2p/``).
        backend: ``"socks5"`` or ``"http-proxy"``. Defaults to HTTP proxy
                 since it's more reliable on most I2P daemons.

        Returns a ``Response`` regardless of success or failure.
        """
        if backend == "socks5":
            return self._socks_request(url)
        else:
            return self._http_proxy_request(url)


# ---------------------------------------------------------------------------
# Approach B — SAM API v3.x client
# ---------------------------------------------------------------------------

class I2PSAMClient:
    """Create and manage explicit client tunnels via SAM (Simple API Machine).

    SAM gives fine-grained control over tunnel creation, lifetime, and data
    flow. The protocol is a line-based text protocol spoken over TCP.

    Parameters
    ----------
    config: optional ``I2PConfig`` with SAM endpoints.  When omitted,
            a default ``I2PConfig()`` is used (127.0.0.1:9025).
    host, port: explicit override for the SAM listener address.
    session_name: label for this tunnel in the daemon.

    Protocol handshake (from i2p spec):

        Client -> Server: VERSION 3.1.0 client=i2p-indexer\\n
        Client <- Server: REPLY OK version=3.1 data=name:value ...\\n
        Client -> Server: basicauth\\n
        Client <- Server: REPLY OK clientName=...\\n clientPassword=...\\n
        Client -> Server: negotiate destname=my-session style=client destination=user:pass\\n
        Client <- Server: REPLY OK port=XXXXX \\n

    After negotiation, the server opens a listening TCP port that you route
    raw HTTP through — it's essentially an inline proxy created on the fly.
    For the ``send`` command (pushing data over an existing session):

        Client -> Server: send bytes=N \\n <N bytes of data>
        Client <- Server: receive bytes=N \\n <N bytes of server response>

    NOTE: SAM is exposed by i2pd on port 9020. The Java I2P daemon (bundled
    router) may expose it on 9025 or not at all. Check your daemon config.
    """

    def __init__(
        self,
        config: Optional[I2PConfig] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        session_name: str = "i2p-indexer-sam",
        timeout: float = 60.0,
    ):
        cfg = config or I2PConfig()
        self.host = host if host is not None else cfg.sam_host
        self.port = port if port is not None else cfg.sam_port
        self.session_name = session_name
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._negotiated_port: Optional[int] = None

    def _write_line(self, line: str) -> None:
        """Send a SAM command (auto-appends newline + flushes)."""
        if self._sock is None:
            raise ConnectionError("SAM client not connected. Call connect() first.")
        logger.debug("SAM >>> %s", line.strip())
        self._sock.sendall((line + "\n").encode())

    def _read_line(self) -> str:
        """Read exactly one response line from the SAM server."""
        if self._sock is None:
            raise ConnectionError("SAM client not connected.")
        buf = b""
        while True:
            chunk = self._sock.recv(1024)
            if not chunk:
                raise ConnectionResetError("SAM server closed connection")
            buf += chunk
            if b"\n" in buf:
                line, remaining = buf.split(b"\n", 1)
                # Push remaining back by storing (we handle simply here)
                decoded = line.decode().strip()
                logger.debug("SAM <<< %s", decoded)
                return decoded

    def connect(self) -> bool:
        """Open TCP connection and negotiate VERSION with the SAM server.

        Returns True if version negotiation succeeded.
        """
        try:
            self._sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            )
        except (ConnectionRefusedError, OSError) as e:
            logger.warning("SAM connection refused: %s", e)
            return False

        self._sock.settimeout(self.timeout)

        try:
            self._write_line("VERSION 3.1.0 client=i2p-indexer")
            resp = self._read_line()
            logger.info("SAM VERSION response: %s", resp)
            if "REPLY OK" in resp:
                self._connected = True
                return True
            else:
                logger.error("SAM version negotiation failed: %s", resp)
                return False
        except ConnectionResetError:
            logger.warning("SAM server closed connection during VERSION handshake")
            return False

    def authenticate(self) -> tuple[str, str]:
        """Run basicauth to get client credentials.

        Returns (client_name, client_password) from the daemon.
        """
        if not self._connected:
            self.connect()
            if not self._connected:
                raise ConnectionError("Cannot authenticate — version negotiation failed")

        self._write_line("basicauth")
        resp = self._read_line()
        
        client_name = ""
        client_password = ""

        # i2pd may send REPLY OK on the first line, then data lines follow
        if "REPLY FAIL" in resp:
            raise ConnectionError(f"SAM basicauth failed: {resp}")

        # Read additional lines for credentials
        while True:
            try:
                line = self._read_line()
                if "clientName=" in line:
                    client_name = line.split("=", 1)[1].strip()
                elif "clientPassword=" in line:
                    client_password = line.split("=", 1)[1].strip()
                if "REPLY OK" in line and client_name and client_password:
                    break
                # Some implementations send REPLY OK on a separate line after data
                if "REPLY OK" in line and not (client_name and client_password):
                    continue
                # Safety: stop reading after 20 lines to avoid hang
                if len(line) < 5 or "REPLY OK" in line:
                    if client_name and client_password:
                        break
            except socket.timeout:
                break

        logger.info("SAM credentials: name=%s, length=%d", client_name, len(client_password))
        return client_name, client_password

    def negotiate(
        self,
        destination_user: str = "",
        destination_pass: str = "",
        style: str = "client",
        general_error: bool = True,
        max_age: int = 3600,
        period: int = 120,
    ) -> Optional[int]:
        """Open a client tunnel via negotiate.

        Returns the local port number assigned by the daemon, or None on failure.
        """
        if not self._connected:
            self.connect()

        dest = f"{destination_user}:{destination_pass}" if (destination_user and destination_pass) else ""
        
        parts = [
            f"negotiate destname={self.session_name}",
            f"style={style}",
        ]
        if dest:
            parts.append(f"destination={dest}")
        parts.append(f"generalErrorNotification={1 if general_error else 0}")
        parts.append(f"period={period}")
        parts.append(f"maxAge={max_age}")

        cmd = " ".join(parts)
        self._write_line(cmd)

        resp = self._read_line()
        logger.info("SAM negotiate response: %s", resp)

        if "port=" in resp:
            port_str = resp.split("port=", 1)[1].split()[0]
            self._negotiated_port = int(port_str)
            return self._negotiated_port

        return None

    def send_data(self, data: bytes) -> bytes:
        """Push raw bytes through an active SAM session and read response.

        Parameters match the SAM ``send`` / ``receive`` commands.
        """
        if not self._connected:
            raise ConnectionError("SAM not connected")

        # Send the data
        cmd = f"send bytes={len(data)}"
        logger.debug("SAM >>> send bytes=%d", len(data))
        self._sock.sendall((cmd + "\n").encode() + data)

        # Read response
        resp = self._read_line()
        logger.debug("SAM <<< %s", resp)

        if "receive bytes=" in resp:
            n = int(resp.split("=", 1)[1].split()[0])
            received = b""
            while len(received) < n:
                chunk = self._sock.recv(min(n - len(received), 4096))
                if not chunk:
                    break
                received += chunk
            return received

        # If the response doesn't match 'receive bytes=N', return empty
        return b""

    def close(self) -> None:
        """Terminate the SAM session."""
        if self._sock:
            try:
                self._write_line("close")
            except Exception:
                pass
            finally:
                self._sock.close()
                self._sock = None
        self._connected = False
        self._negotiated_port = None

    # -- Convenience wrapper ------------------------------------------------

    def fetch(self, url: str) -> Response:
        """Fetch a URL through the SAM tunnel.

        This opens a session, creates a client tunnel, sends an HTTP request
        through it, and returns a ``Response``.
        """
        start = time.monotonic()

        try:
            self.connect()
            if not self._connected:
                return Response(url=url, status=0, elapsed=0, via=ProxyBackend.SAM)

            # Try to authenticate and negotiate
            user, passwd = self.authenticate()
            
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or "destination.i2p"
            port = parsed.port or 80
            path = parsed.path if parsed.path else "/"
            query = f"?{parsed.query}" if parsed.query else ""

            # Build an HTTP request over the SAM tunnel
            http_req = (
                f"GET {path}{query} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: I2PIndexer/0.1\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )

            data = http_req.encode()
            resp_bytes = self.send_data(data)

        except Exception as e:
            elapsed = time.monotonic() - start
            logger.warning("SAM fetch to %s failed: %s", url, e)
            return Response(
                url=url, status=0, body=b"", elapsed=round(elapsed, 2), via=ProxyBackend.SAM
            )
        finally:
            self.close()

        # Parse HTTP response from the daemon
        status = 0
        headers = {}
        body = b""
        try:
            text = resp_bytes.decode("utf-8", errors="replace")
            parts = text.split("\r\n\r\n", 1)
            if len(parts) == 2:
                header_block, body_str = parts
                header_lines = header_block.split("\r\n")
                if header_lines:
                    status_line = header_lines[0]
                    try:
                        status = int(status_line.split(" ", 2)[-1].split()[0])
                    except (ValueError, IndexError):
                        pass
                    for hl in header_lines[1:]:
                        if ":" in hl:
                            k, v = hl.split(":", 1)
                            headers[k.strip()] = v.strip()
                body = body_str.encode("utf-8") if isinstance(body_str, str) else body_str
        except Exception:
            body = resp_bytes

        elapsed = time.monotonic() - start
        return Response(
            url=url, status=status, headers=headers, body=body,
            elapsed=round(elapsed, 2), via=ProxyBackend.SAM,
        )


# ---------------------------------------------------------------------------
# Unified fetch helper
# ---------------------------------------------------------------------------

def fetch_i2p(
    url: str,
    via: str = "socks",
    timeout: float | None = None,
    config: Optional[I2PConfig] = None,
) -> Response:
    """Fetch an eepsite URL through the I2P proxy.

    Parameters
    ----------
    url: full .i2p URL (``http://something.i2p/``).
    via: backend to use — ``"socks"``, ``"http-proxy"``, or ``"sam"``.
         Defaults to ``"socks"`` which automatically falls back to HTTP proxy.
    timeout: optional per-call timeout in seconds. If None, uses the client
             default (120s). Useful for overriding on a per-target basis.
    config: optional ``I2PConfig`` with proxy endpoints.  When omitted,
            a default ``I2PConfig()`` is created.

    Returns a ``Response`` object (always non-exception-raising).
    """
    client = I2PProxyClient(config=config, timeout=timeout) if timeout is not None else I2PProxyClient(config=config)

    if via == "socks":
        logger.info("Trying SOCKS5 for %s", url)
        r = client.request(url, backend="socks5")
        # If SOCKS5 returned status 0 (failure), fall back to HTTP proxy
        if not r.status:
            logger.warning("SOCKS5 failed for %s, falling back to HTTP proxy", url)
            return client.request(url, backend="http-proxy")
        return r

    elif via == "sam":
        logger.info("Trying SAM for %s", url)
        sam = I2PSAMClient(config=config, timeout=timeout) if timeout is not None else I2PSAMClient(config=config)
        return sam.fetch(url)

    else:  # http-proxy
        logger.info("Using HTTP proxy for %s", url)
        return client.request(url, backend="http-proxy")


# ---------------------------------------------------------------------------
# Protocol fingerprinting — TCP banner grab before HTTP probe
# ---------------------------------------------------------------------------

# Table-driven protocol signatures. Order matters — HTTP first because many
# services start with text that looks like other protocols, and we want to
# catch the most common case first.
_PROTOCOL_SIGNATURES: list[tuple[str, str, int]] = [
    # (tag, prefix_to_match, match_length)
    ("http/web", "HTTP/1.", 7),
    ("smtp/nntp", "+OK ", 4),
    ("smtp/nntp", "220 ", 4),
    ("irc_gateway", " :Welcome to IRC", 16),
    ("irc_gateway", " :Your host is", 14),
    ("bob_bridge", "BOB ", 4),
]


def probe_tcp_banner(
    host: str,
    port: int = 80,
    timeout: float = 3.0,
    max_read: int = 50,
    config: Optional[I2PConfig] = None,
) -> tuple[str, bytes]:
    """Connect to *host*:*port* via SOCKS5 proxy and read up to *max_read* bytes.

    Returns (tag, raw_banner) where *tag* is one of the protocol labels or
    "unknown/tcp" if nothing matched.  The raw banner is at most *max_read*
    bytes from the first recv(); a service that sends nothing within the timeout
    returns ("closed", b"").

    Uses PySocks monkey-patching so the connection travels through the I2P
    tunnel without opening a new one — the SOCKS5 proxy (default port 7656)
    is reused.
    """
    cfg = config or I2PConfig()
    import socks

    _original_socket = socket.socket
    banner = b""
    try:
        socks.set_default_proxy(
            socks.PROXY_TYPE_SOCKS5, cfg.socks_host, cfg.socks_port
        )
        socket.socket = socks.socksocket

        raw_sock = socket.create_connection((host, port), timeout=timeout)
        try:
            _start = time.monotonic()
            banner = raw_sock.recv(max_read)
        finally:
            raw_sock.close()
    except OSError:
        return ("unreachable", b"")
    finally:
        socket.socket = _original_socket

    if not banner:
        return ("closed", b"")

    tagged = _fingerprint_protocol(banner)
    return (tagged, banner[:max_read])


# Byte-string regex patterns for protocol detection.
# Raw bytes literal (rb'...') — \s means actual whitespace in the pattern.
_PROTOCOL_PATTERNS_RE: list[tuple[str, re.Pattern[bytes]]] = [
    ("bob_bridge", re.compile(rb"^BOB\s")),
    ("bittorrent_tracker", re.compile(rb"(announce|peers|info_hash|complete\s)")),
]


def _fingerprint_protocol(banner: bytes) -> str:
    """Match *banner* against the protocol signature table.

    Returns a stable tag string like "http/web" or "unknown/tcp".
    Checks both fixed prefixes and regex patterns.
    """
    # 1. Fixed prefix matches (fast path, handles >90% of cases)
    for tag, prefix, length in _PROTOCOL_SIGNATURES:
        if banner[:length].decode("ascii", errors="ignore") == prefix:
            return tag

    # 2. Regex pattern matches (slower, catches partial/signature banners)
    try:
        text = banner.decode("ascii", errors="replace").upper()
    except Exception:
        text = ""

    for tag, pattern in _PROTOCOL_PATTERNS_RE:
        if pattern.search(banner):
            return tag

    # 3. Heuristics for common non-HTTP services detectable by structure
    if b"<stream" in banner[:50] or b"</streamelement>" in banner[:50]:
        return "xmpp/jabber"
    if banner.startswith(b"\x00\x01") or len(banner) == 0:
        # TLS/NULL banners are common on SMTP
        return "smtp/tls"

    return "unknown/tcp"


# ---------------------------------------------------------------------------
# Helpers for testing
# ---------------------------------------------------------------------------

def probe_health(via: str = "socks") -> bool:
    """Quick check: can we reach ANY known .i2p address?

    Returns True if at least one well-known site responds (even with a 502,
    that proves the tunnel is established and traffic flows).
    """
    targets = [
        "http://i2pstat.i2p/",
        "http://i2p-projekt.i2p/",
        "http://huggingface.github.io/i2p/",  
    ]
    for target in targets:
        try:
            r = fetch_i2p(target, via=via)
            if r.status > 0:
                logger.info("Health OK via %s — got status %d from %s", via, r.status, target)
                return True
        except Exception as e:
            logger.warning("Health probe %s failed: %s", target, e)
    return False


# urllib modules imported at the top of this file.
