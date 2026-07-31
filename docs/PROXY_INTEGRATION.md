# Proxy Integration Guide

## Overview

The I2P indexer communicates with a local I2P daemon through three possible backends:

| Backend | Port | Status | Description |
|---|---|---|---|
| HTTP CONNECT proxy | 4444 | ✅ Primary | Routes HTTP requests via the daemon's built-in proxy |
| SOCKS5 proxy | 7656 | ✅ Fallback | Standard SOCKS5 routing through PySocks |
| SAM v3.x API | 9025 | ❌ Not exposed | Creates named tunnels programmatically (disabled in Docker config) |

The HTTP proxy is the default and preferred path. SOCKS5 activates on failure. SAM exists as scaffolding for future use.

## Proxy Backend Selection Flow

```
fetch_i2p(url, via="http-proxy")
        │
        ▼
   ┌─────────────┐     success      ┌──────────┐
   │  HTTP PROXY │ ───────────────►  │ Response │
   │  :4444      │                  └──────────┘
   └──────┬──────┘
          │ failure (timeout / connection refused)
          ▼
   ┌─────────────┐     success      ┌──────────┐
   │  SOCKS5     │ ───────────────►  │ Response │
   │  :7656      │                  └──────────┘
   └──────┬──────┘
          │ failure
          ▼
   raise ConnectionError("all backends unavailable")
```

## The `fetch_i2p()` Helper

The unified entry point in `src/i2p_proxy.py`:

```python
from src.i2p_proxy import fetch_i2p, ProxyBackend

r = fetch_i2p("http://i2p-projekt.i2p/", via="http-proxy")
print(r.status)      # 200
print(len(r.body))   # response bytes
print(r.text[:80])   # decoded text snippet
print(r.title())     # "<title>" extracted from HTML
```

Returns a `Response` dataclass with:

| Attribute | Type | Description |
|---|---|---|
| `url` | str | Requested URL |
| `status` | int | HTTP status code (0 on connection failure) |
| `headers` | dict | Response headers |
| `body` | bytes | Raw response body |
| `encoding` | str | Character encoding |
| `elapsed` | float | Round-trip time in seconds |
| `via` | ProxyBackend | Backend that was used |

## Dual-Mode Probing Strategy

The integration layer (`src/integration.py`) implements a **hash-first, DNS-second** approach:

```python
# Step 1: Try direct hash address (b32) — no SUSI/SU3 resolution needed
try:
    b32_url = f"http://{ident_hash.b32.i2p}/"
    resp = fetch_i2p(b32_url, via="http-proxy")
except Exception:
    pass

# Step 2: Try human-readable .i2p DNS name (fallback)
if dns_name:
    try:
        dns_url = f"http://{dns_name}/"
        resp = fetch_i2p(dns_url, via="http-proxy")
    except Exception:
        pass

# Record which path(s) succeeded
via_method = "b32" | "dns" | "b32+dns" | ""
```

**Why hash-first?** Base32 addresses encode the destination's actual identity. No external DNS service (SU3/SUSI) is required — the request goes directly to the network overlay. This makes b32 probing dramatically more reliable, especially when:
- The local router's SU3 cache is stale
- External SUSI services are unreachable
- The destination has no registered `.i2p` hostname

## Known Address Formats

The probe system accepts three target formats:

| Format | Example | Behavior |
|---|---|---|
| `(hash_hex, dns_name)` tuple | `("F957...", "site.i2p")` | **Both** b32 and DNS attempted (preferred) |
| Bare `.i2p` hostname | `"forum.example.i2p"` | **DNS-only** (no hash available) |
| Bare `.b32.i2p` address | `"abcdefg...b32.i2p"` | **Hash-first only** |

## Health Checks

```python
from src.i2p_proxy import probe_health

health = probe_health()
# Returns dict: {'backend': 'http-proxy', 'status': 'ok', 'latency_ms': 45}
# or on failure:  {'backend': 'http-proxy', 'status': 'down', 'error': '...'}
```

This is the recommended way to verify daemon connectivity before launching a probe session. Latency above ~2 seconds usually indicates I2P network congestion rather than local issues.

## Timeout and Retry Policy

- Individual request timeout: **5 seconds** (configurable per-fetch)
- Backend switch delay: immediate (no retry of failed backend; instant fallback to SOCKS5)
- Full probe session timeout: unlimited — each destination is independent

The daemon itself may be slow during bootstrapping. A healthy I2P tunnel typically responds within 1–3 seconds for cached destinations. First-contact destinations can take 10+ seconds due to introducter resolution.

## Security Considerations

- All proxy communication stays on `127.0.0.1` — no credentials leave the host
- No authentication is required by default (local-only daemon)
- Request paths and headers are visible to the I2P router but opaque to external observers
- Never pass user secrets (API keys, passwords) in request bodies to untrusted `.i2p` destinations
