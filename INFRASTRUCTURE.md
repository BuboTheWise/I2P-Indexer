# Infrastructure

## I2P Daemon (Local)
- **Type**: Java I2P router in Docker container
- **Host ports mapped**: 4444 (HTTP proxy), 7654 (webconsole), 7656 (SOCKS5)
- **Docker access**: User cannot connect to Docker socket; netdb files inside container are NOT accessible from host

## Project Dependencies
See `requirements.txt` for full list. Key packages:
- `httpx`, `PySocks` - I2P proxy connectivity (HTTP + SOCKS5)
- `protobuf`, `grpcio-tools` - Protocol buffer support for future extensibility
- `pytest` - Test framework

## Data Sources
1. **Primary**: netdb files inside Docker container (`.rtr` binary, `.ls64` base64)
2. **Fallback**: Java I2P webconsole at `http://127.0.0.1:7657/peers`

## Limitations
- SOCKS5 proxy at port 7656 accepts TCP but resets on handshake (Java router quirk)
- Webconsole at 7654 returns HTML, not JSON — requires HTML scraping fallback
- No direct netdb filesystem access; must rely on webconsole for live data
