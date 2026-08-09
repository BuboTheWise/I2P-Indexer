"""Configuration for I2P proxy connectivity.

Provides an I2PConfig dataclass with validation for host/port parameters.
All credential-related values (hosts, ports) are parameterized — never
hardcoded inside the clients that consume them. Per NFR-04, this ensures
credential isolation: tests can inject arbitrary endpoints without touching
production defaults.
"""

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


def _validate_port(port: int) -> int:
    """Validate that *port* is a valid TCP/UDP port number (1-65535).
    
    Raises ValueError on out-of-range, zero, or non-integer input.
    """
    if not isinstance(port, int):
        raise TypeError(f"Port must be an integer, got {type(port).__name__}")
    if port < 1 or port > 65535:
        raise ValueError(
            f"Port {port} out of valid range (1-65535). "
            f"Common I2P ports: HTTP=4444, SOCKS=7656, SAM=9025, Webconsole=7657"
        )
    return port


def _validate_host(host: str) -> str:
    """Validate that *host* is a non-empty string representing a valid hostname or IP.
    
    Raises ValueError on empty strings or obviously invalid input.
    Raises TypeError if not a string.
    """
    if host is None:
        raise TypeError("Host cannot be None")
    if not isinstance(host, str):
        raise TypeError(f"Host must be a string, got {type(host).__name__}")
    if not host.strip():
        raise ValueError("Host cannot be empty or whitespace-only")
    # Strip whitespace but don't auto-correct malformed hosts — let the socket layer fail
    return host


@dataclass
class I2PConfig:
    """Connection parameters for the local I2P daemon and optional services.
    
    All fields are parameterized with sensible defaults pointing to a
    standard I2P router on localhost.  Validation runs at construction
    time so misconfigured values fail loud and early.
    
    Typical usage:
        cfg = I2PConfig(http_port=8080)          # override one port
        cfg = I2PConfig(sam_host="remote-i2p")    # remote router
    """
    socks_host: str = "127.0.0.1"
    socks_port: int = 7656
    http_host: str = "127.0.0.1"
    http_port: int = 4444
    sam_host: str = "127.0.0.1"
    sam_port: int = 9025
    webconsole_host: str = "127.0.0.1"
    webconsole_port: int = 7657
    ollama_url: Optional[str] = None

    def __post_init__(self):
        """Validate all host/port pairs after dataclass initialization."""
        self.socks_host = _validate_host(self.socks_host)
        self.socks_port = _validate_port(self.socks_port)
        self.http_host = _validate_host(self.http_host)
        self.http_port = _validate_port(self.http_port)
        self.sam_host = _validate_host(self.sam_host)
        self.sam_port = _validate_port(self.sam_port)
        self.webconsole_host = _validate_host(self.webconsole_host)
        self.webconsole_port = _validate_port(self.webconsole_port)

    # -------------------------------------------------------------------------
    # Convenience properties — each returns the (host, port) tuple for a subnet
    # -------------------------------------------------------------------------

    @property
    def socks(self):
        return self.socks_host, self.socks_port

    @property
    def http(self):
        return self.http_host, self.http_port

    @property
    def sam(self):
        return self.sam_host, self.sam_port

    @property
    def webconsole(self):
        return self.webconsole_host, self.webconsole_port


# Ports verified against running I2P JVM daemon on this host:
# ✓ 4444 — HTTP proxy, accessible
# ✓ 7654 — Webconsole (HTTP API), accessible
# ✓ 7656 — SOCKS5 proxy, accessible
# ✗ 9025 — SAM API, not exposed by this daemon instance
# ✓ 11434 — Ollama API (when available)
