# Docker Infrastructure for I2P Indexer

This folder contains the Docker Compose configuration and supporting files needed to set up the I2P router and an nginx web server **from scratch**.

## Purpose

These files are provided as a convenience to replicate the development / reference environment. They spin up:

- **`i2p`** — The official [geti2p/i2p](https://hub.docker.com/r/geti2p/i2p) router container with HTTP/HTTPS/SAM proxies and networking ports exposed on `localhost`.
- **`nginx`** — A minimal nginx server that serves static files from the `../webroot/` directory. The I2P router can reach this service over the Docker network (e.g., `http://nginx`) for eepsite / HTTP proxy routing.

## ⚠️ Not required to run the indexer

The I2P Indexer project does **not** depend on Docker to function. It only needs an I2P router running somewhere (bare metal, another container, a VPS — your call) with the relevant ports reachable. These compose files are meant to help new contributors or users who want a quick-start environment that mirrors our setup.

## Quick start

```bash
# From the docker/ directory:
docker compose up -d
```

Docker will create the network, pull images, and start both services. After booting you can reach the router console at `http://localhost:7657`.

## File layout

| File | Description |
|---|---|
| `docker-compose.yml` | Defines the `i2p` and `nginx` services on a shared Docker network |
| `nginx.conf` | Minimal nginx config serving static files from `../webroot/` |
| `README.md` | This file |

## Notes

- All service ports are bound to `127.0.0.1` so they are only reachable on the host — no inbound exposure beyond localhost.
- The I2P configuration directory (`./i2pconfig`) and snark data (`./i2ptorrents`) are created at first run and persist across restarts.
- Place any web content you want served by nginx in the `webroot/` folder inside this directory.
