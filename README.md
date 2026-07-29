# I2P eepsite indexer

Client-side tool that reads the local I2P addressbook, parses destination metadata, and probes known eepsites through a pre-running I2P proxy — no browser required. Everything runs as `python3` scripts with SOCKS5/SAM connectivity.

## Architecture

- **I2P daemon** — already running locally (Docker container), out of scope for this project
  - SOCKS5 on `127.0.0.1:7656`
  - HTTP proxy on `127.0.0.1:4444`
  - Webconsole on `127.0.0.1:7654`
- **proxy/** — SOCKS5 client wrapper + SAM API interface for building/breaking tunnels
- **netdb/** — Parser for I2P .nb addressbook files and webconsole JSON API
- **indexer/** — Orchestrator that combines parsed destinations with proxy connectivity to discover live sites

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pysocks httpx pytest  # TODO: move into pyproject.toml dependencies
pytest tests/
echo "I2P indexer is working."
```
