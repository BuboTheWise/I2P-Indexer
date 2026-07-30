"""Proxy connectivity layer for I2P.

Provides two interfaces:
- SOCKS5 proxy via httpx + pysocks (simple HTTP over tunnel)
- SAM v3.1 API for creating/breaking named tunnels programmatically
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

@dataclass
class I2PConfig:
    """Connection parameters for the local I2P daemon."""
    socks_host: str = "127.0.0.1"
    socks_port: int = 7656
    http_host: str = "127.0.0.1"
    http_port: int = 4444
    sam_host: str = "127.0.0.1"
    sam_port: int = 9025
    webconsole_host: str = "127.0.0.1"
    webconsole_port: int = 7657

# Ports verified against running I2P JVM daemon on this host:
# ✓ 4444 — HTTP proxy, accessible
# ✓ 7654 — Webconsole (HTTP API), accessible
# ✓ 7656 — SOCKS5 proxy, accessible
# ✗ 9025 — SAM API, not exposed by this daemon instance
