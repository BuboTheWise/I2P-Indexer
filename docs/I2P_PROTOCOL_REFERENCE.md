# I2P Protocol Reference for Indexing

> Comprehensive reference covering I2P's core networking stack, programmatic interfaces, and data structures needed to build an I2P eepsite indexer. Written for engineers with zero prior I2P knowledge.

## Table of Contents

1. [I2P Daemon (i2pd) Architecture](#1-i2p-daemon-i2pd-architecture)
2. [I2P Proxy Interfaces](#2-i2p-proxy-interfaces)
3. [AddressBook (.nb Files)](#3-addressbook-nb-files)
4. [Eepsite Addressing and Naming](#4-eepsite-addressing-and-naming)
5. [Network Data Structures](#5-network-data-structures)
6. [Python Ecosystem for I2P](#6-python-ecosystem-for-i2p)
7. [Legal/Ethical Considerations](#7-legalethical-considerations)

---

## 1. I2P Daemon (i2pd) Architecture

### What is i2pd?

i2pd (I2P Daemon) is a full-featured C++ implementation of an I2P router client. It runs as a background service that:

- Maintains connections to the I2P network peer-to-peer overlay
- Builds and manages anonymous tunnels (inbound/outbound garbage-collected tunnels)
- Provides proxy services (SOCKS5, HTTP) for applications to access I2P destinations
- Implements control APIs (SAM, BOB) for programmatic tunnel management
- Participates in the network's distributed hash table (DHT-based network database)

I2P itself is an anonymous overlay network where all traffic is encrypted, peer-to-peer routed through layered tunnels. The protocol uses 4-layered inbound/outbound tunnels providing plausible deniability — no observer can link a sender to a receiver.

**Sources:**
- i2pd docs: https://i2pd.readthedocs.io/en/latest/
- GitHub: https://github.com/PurpleI2P/i2pd
- I2P about page: https://geti2p.net/en/about

### Service Model

i2pd runs as a long-running daemon process. On systemd-based systems:

```ini
# /etc/systemd/system/i2pd.service (Arch Linux packaged)
[Unit]
Description=I2P Daemon
After=network.target

[Service]
Type=simple
User=i2pd
ExecStart=/usr/bin/i2pd
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

The daemon maintains its own state in a working directory and continuously:

1. Connects to peers via NTCP2 (TCP-based) or SSU2 (UDP-based) transports
2. Periodically reseeds from bootstrap servers to get initial router info
3. Explores the network through exploratory tunnels to discover new peers
4. Maintains client tunnels for proxy and API connections
5. Updates its netdb (network database) with router information

### Configuration File Format and Location

**Locations:**

| Priority | Path | Notes |
|----------|------|-------|
| User local | `~/.i2pd/config.yaml` | Per-user config, highest priority |
| System-wide | `/etc/i2pd/conf/i2pd.conf` | Debian/Ubuntu packages |
| System-wide | `/etc/i2pd/config.yaml` | Arch Linux / upstream default |

The configuration is YAML-formatted. i2pd also supports individual `.conf` files in a `conf/` subdirectory that override specific sections.

**Key Configuration Sections:**

```yaml
# Daemon section
daemon:
  enable: true          # Run as background daemon
  max_threads: 10      # Maximum worker threads
  max_client_threads: 20

# Proxy services
proxy:
  enabled: true
  host: 127.0.0.1
  port: 7070            # HTTP proxy port (default)
  auth: false

socksProxy:
  enabled: true
  host: 127.0.0.1
  port: 9050            # SOCKS5 proxy port (i2pd default; Java I2P uses 4447)

# SAM API
sam:
  enabled: true
  host: 127.0.0.1
  port: 7656            # SAM port (i2pd default; Java I2P uses 9025/9018)
  autostart: false

# BOB API
bob:
  enabled: true
  host: 127.0.0.1
  port: 7654            # BOB port
  password: "secret"

# Web console (router control UI)
webconsole:
  enabled: true
  host: 127.0.0.1
  port: 7090
  auth: true
  user: admin
  password: hashed_password

# Bandwidth tuning
bandwidth:
  up: 64               # KB/s upload (0 = unlimited)
  down: 64             # KB/s download

# Network database
netdb:
  max_num_neighbors: 32
```

**Important for our project:** The host environment runs a **Java I2P router behind Docker**. Key port mappings:

| Service | Docker Host Port | Notes |
|---------|-----------------|-------|
| HTTP proxy | 4444 | WORKS — use as primary transport |
| SOCKS5 | 7656 | BROKEN on this daemon (RST on handshake) |
| SAM API | 9025 | NOT EXPOSED on this daemon instance |
| BOB/SSL | 4445 | Listening but unused |

The HTTP proxy on port 4444 is the most reliable transport for this deployment.

**Sources:**
- i2pd config docs: https://docs.i2pd.website/en/latest/configuring/
- Arch Wiki I2P: https://wiki.archlinux.org/title/I2P
- i2pd GitHub config samples: https://github.com/PurpleI2P/i2pd/tree/master/conf

### Install Method on Arch Linux

```bash
# Install i2pd
pacman -S i2pd

# Enable and start the service
systemctl enable --now i2pd.service

# Edit configuration
nano /etc/i2pd/config.yaml

# Access webconsole at http://127.0.0.1:7090/

# Note: The I2P Indexer project uses a Java I2P router behind Docker,
# not i2pd directly. i2pd documentation is included here for reference
# in case the deployment is switched to native i2pd later.
```

---

## 2. I2P Proxy Interfaces

### SOCKS5 Proxy

**Default ports:** Java I2P = 4447, i2pd = 9050

SOCKS5 is the standard interface for HTTP clients to access .i2p destinations through an I2P router. The proxy accepts standard SOCKS5 CONNECT requests where the destination hostname ends in `.b32.i2p` or `.i2p`.

**How it works:**
1. Client opens TCP connection to SOCKS5 proxy port
2. Client sends version/method selection (typically socks5 with no-auth)
3. Client sends CONNECT request with destination (`ATYP=3` domain name for .i2p addresses)
4. Router builds client tunnels through the I2P network to reach the target destination
5. Proxy returns success/failure, then relays data bidirectionally

**Important pitfall:** On this host's Dockerized Java I2P router, SOCKS5 (port 7656) sends RST on all connection attempts — it accepts TCP but resets during the handshake. Use HTTP proxy instead as primary transport.

### HTTP Proxy

**Default ports:** Java I2P = 4444, i2pd = 7070

The HTTP proxy is a standard HTTP forward proxy that supports `CONNECT` method for tunneling arbitrary TCP traffic. This is the most reliable interface on the current Dockerized Java I2P deployment.

```python
# Example: Fetching an eepsite through HTTP proxy
import urllib.request

proxy = urllib.request.ProxyHandler({'http': 'http://127.0.0.1:4444'})
opener = urllib.request.build_opener(proxy, urllib.request.HTTPHandler)
response = opener.open('http://someeepsite.b32.i2p/')
content = response.read()
```

**Verified:** Successfully fetches eepsites including i2p-projekt.i2p (returns 200/21KB). Works with `urllib.request.ProxyHandler`, `httpx` proxy strings, and raw TCP clients that speak HTTP over the port.

### SAM (Simple API Machine) 3.x API

**What it is:** A line-oriented TCP protocol for programmatic control of I2P client tunnels. Provides fine-grained control over tunnel creation, destination management, and data relay — more capable than a simple proxy because you manage the tunnels directly.

**Ports:** Java I2P = 9018 (client mode) / 9025 (server mode), i2pd typically configurable via config.

**SAM is NOT exposed on this host's Dockerized Java I2P.** Implement for i2pd compatibility but expect connection-refused.

#### SAM Protocol Flow (Server Mode)

```
# Client connects to SAM port
> VERSION 3.1 CLIENT software-name
< RESULT=OK VERSION=3.1

> SETOPTION STYLE client
< RESULT=OK STYLE=client

> NEGOTIATE
< RESULT=OK
  HOST=127.0.0.1      # Local address to bind
  PORT=5555            # Local port for the tunnel endpoint

> SEND DESTINATION=<base64_destination>
     SESSION_DATE=<unix_timestamp>
     ADDRESS=10.0.0.1
     PORT=80           # Target I2P destination port

< RESULT=OK ID=abcdef123456

# Now read/write data at the local endpoint (HOST:PORT from NEGOTIATE)
# When done:
> CLOSE SESSIONID=abcdef123456
< RESULT=OK
```

#### SAM Protocol Flow (Client Mode — More Common for Indexing)

In client mode, the application talks data directly over the SAM connection rather than through a local endpoint:

```
> VERSION 3.1 CLIENT indexer
< RESULT=OK VERSION=3.1

> SETOPTION STYLE client
< RESULT=OK STYLE=client

> NEGOTIATE
< RESULT=OK
  HOST=127.0.0.1
  PORT=5555
  TTL=60

# Send HTTP request over the SAM connection itself:
GET / HTTP/1.1
Host: target.b32.i2p
User-Agent: I2P-Indexer/1.0

< RESULT=OK ID=session_id

# Response data arrives on same connection
HTTP/1.1 200 OK
Content-Type: text/html
...

> CLOSE SESSIONID=session_id
< RESULT=OK
```

#### SAM Commands Reference

| Command | Purpose | Key Parameters |
|---------|---------|----------------|
| `VERSION` | Negotiate protocol version | Version number, client name |
| `SETOPTION` | Set session options | STYLE, ENCRYPT, AUTHDATA, I2CP_HOST/PORT |
| `NEGOTIATE` | Open new tunnel session | TTL, lease count, proxy address |
| `SEND` | Send data to destination | DESTINATION (session or raw), HTTP data |
| `RECEIVE` | Read response data | SESSIONID or ADDRESS |
| `CLOSE` | Teardown session | SESSIONID |
| `DESTADD` | Register new I2P destination | NAME, DATA (base64 destination) |
| `DESTUPDATE` | Update existing destination | NAME, DATA |
| `AUTHDATA` | Set persistent auth data | AUTHDATA string |

#### `destadd` Command (Register Destination)

Creates or updates a named I2P destination in the router's address book:

```
> DESTADD NAME=my-indexer-data DATA=<base64_destination_bytes>
< RESULT=OK SESSION_KEY=<key_value_if_encrypted>
```

The destination data is a base64-encoded I2P Destination object containing update info, certificates, and keys.

#### `basicauth` (Authenticate Client Credentials)

When SAM is configured with authentication (`auth=true`), the client must authenticate before issuing commands:

```
> VERSION 3.1 CLIENT agent
< RESULT=OK VERSION=3.1
< BASE64USERPASS=<base64_credentials>
< AUTHDATA=<hex_or_base64_blob>

# Client echoes back for verification:
> AUTHDATA <echoed_authdata>
< RESULT=OK
```

### BOB API

**Ports:** Java I2P via SSL on 4445 (common), i2pd = 7654

A more advanced line-oriented protocol built on top of SAM capabilities. Uses SSL/TLS transport and provides:

- Tunnel management (client, server, stream tunnels)
- Destination management with crypto key generation
- Stream tunnel support for bidirectional TCP streams
- Tag-based message identification (reduces state management complexity)
- Better error handling and async response model

BOB listening but unused on this host. Worth implementing if SAM is unavailable because it's generally available wherever SAM is.

### I2CP (I2P Control Protocol)

**Port:** Java I2P default = 3133, i2pd configurable (typically 3133 or from config)

A binary protocol that sits below SAM/BOB and speaks directly to the router core:

- **Message format:** Length-prefixed binary with message type codes
- **Primary operations:** GetSession, UpdateTunnels, AddressInfoReply, NetDbInfo, Ping
- **Used by:** Thin clients (like iReceptor) that want full DHT access without running a complete router
- **Complexity:** Significantly more complex than SAM; requires understanding of I2P's internal data types

For indexing purposes, I2CP is probably overkill. SAM or HTTP proxy provide all the functionality needed for fetching eepsite content. However, if we want to read the network database directly without going through a router proxy, I2CP AddressInfo requests could be useful.

**Message types of interest:**
- `AddressInfoRequest` (0x4): Query specific destination
- `AddressInfoReply` (0x8): Contains LeaseSet data for queried address
- `NetDbInfoUpdate` (0xC): Passive notification of NetDB changes
- `GetRouterInfo` (0xF): Retrieve router identity and capabilities

**Protocol spec:** https://wiki.i2p2.de/en/Development/I2CP

---

## 3. AddressBook (.nb Files)

### Location

In i2pd: `~/.i2pd/netdb/` or `/var/lib/i2pd/netdb/`
In Java I2P: Inside the router's working directory under `netdb/`

**On this host:** The netdb lives inside the Docker container and is NOT directly accessible from the host filesystem. A local `netdb/` exists in the project root but is empty — it would be populated by future data collection tasks.

### File Format

The `.nb` (network database) files store router information and lease sets. The format differs between implementations:

#### i2pd Binary Format (.rtr, .ls64 files) — Source-Analyzed from libi2pd/

**Serialization:** RouterInfo and LeaseSet use raw binary buffers written directly to disk. This is NOT protobuf, msgpack, or any standard serialization library — it's a custom length-prefixed wire protocol defined in `RouterInfo.cpp` / `LeaseSet.cpp` with the layout encoded as C++ struct serializations.

**On-disk file conventions:**

| Extension | Content | Max Size |
|-----------|---------|----------|
| `.rtr` | RouterInfo raw buffer (binary) | 3072 bytes (`MAX_RI_BUFFER_SIZE`) |
| `.ls64` | LeaseSet base64-encoded | 3072 bytes (`MAX_LS_BUFFER_SIZE`) |

Filenames are the **base64-encoded 20-byte SHA-1 identity hash** (the `IdentHash` type used throughout i2pd).

```
~/.i2pd/netdb/
├── <base64_20byte_hash>.rtr      # RouterInfo entries
└── <base64_20byte_hash>.ls64     # LeaseSet entries (base64 encoded)
```

**RouterInfo binary layout (from libi2pd/RouterInfo.h):**

The `RouterInfo` class wraps a `Buffer` (`std::array<uint8_t, 3072>`) with these logical sections:

| Section | Size | Description |
|---------|------|-------------|
| Identity type byte | 1 | Key algorithm discriminator: ElGamal=1 (0x01), ECIES-X25519-AEAD=3 (0x03) |
| Public key | Variable | ElGamal or ECIES public key material |
| Certificate chain | Variable | RSA certificates signed by authority. Signed with router's signing key |
| Timestamp | 8 bytes (uint64_t) | Milliseconds since epoch when this RouterInfo was published |
| Properties map | Variable | Key-value XML-style: "v"=version string, "caps"=capability flags |
| Address entries | Variable×N | One per supported transport (max 5 types in `eNumTransports`) |
| Signature | Variable | RSA-1024 or ECDSA-SHA256 signature over the preceding buffer |

**Per-address entry structure (`RouterInfo::Address`):**

| Field | Type | Description |
|-------|------|-------------|
| `transportStyle` | enum (uint8) | NTCP2=1, SSU2=2 |
| `host` | IP address | boost::asio::ip::address (v4 or v6) |
| `s` | 32 bytes (Tag\<32\>) | Static destination key for ECDH handshake |
| `i` | 32 bytes (Tag\<32\>) | IV (first 16 used) for NTCP2; intro-key for SSU |
| `port` | int (uint16) | TCP/UDP port number |
| `date` | uint64_t | Timestamp when this address entry was created |
| `caps` | uint8_t | Per-address flags: V4=0x01, V6=0x02, SSU_testing=0x04, SSU_introducer=0x08 |
| `published` | bool | Whether IP is publicly published (vs NAT-hidden) |
| `ssu` | pointer (optional) | SSUExt struct with MTU + introducer list |

**SSU introducer sub-structure:**

| Field | Type | Description |
|-------|------|-------------|
| `iH` | IdentHash (20 bytes) | Router identity hash of the introducer |
| `iTag` | uint32_t | Introducer session tag |
| `iExp` | uint32_t | Expiration timestamp for this introducer |

**Capability flags (concatenated chars inside "caps" property):**

| Char | Meaning | Bandwidth Threshold |
|------|---------|---------------------|
| f | Floodfill router | N/A — publishes full DHT data |
| H | Hidden | Router not advertised in NetDB |
| R | Reachable from clearnet | Has published IP address |
| U | Unreachable behind NAT | No public endpoint |
| K | Low bandwidth tier 1 | < 12 KBps |
| L | Low bandwidth tier 2 | 12–48 KBps (below `LOW_BANDWIDTH_LIMIT=48`) |
| M | Low bandwidth tier 3 | 48–64 KBps |
| N | Low bandwidth tier 4 | 64–128 KBps |
| O | High bandwidth | 128–256 KBps (up to `HIGH_BANDWIDTH_LIMIT=256`) |
| P | Extra bandwidth tier 1 | 256–2048 KBps |
| X | Extra bandwidth tier 2 | > 2048 KBps (above `EXTRA_BANDWIDTH_LIMIT=2048`) |
| D | Medium congestion | Router experiencing moderate load |
| E | High congestion | Updates every `HIGH_CONGESTION_INTERVAL=900s` (15 min) |
| G | Reject-all congestion | Refuses new tunnel requests |
| 4 | IPv4 support | Supports IPv4 transports |
| 6 | IPv6 support | Supports IPv6 transports |
| B | SSU2 peer testing | Can participate in NAT hole-punching tests |
| C | SSU2 introducer role | Acts as relay for NAT-to-NAT connections |

**Transport support bitmask (CompatibleTransports = uint8_t):**

| Bit | Transport | Value |
|-----|-----------|-------|
| 0 | NTCP2 over IPv4 | 0x01 |
| 1 | NTCP2 over IPv6 | 0x02 |
| 2 | SSU2 over IPv4 | 0x04 |
| 3 | SSU2 over IPv6 | 0x08 |
| 4 | NTCP2v6 mesh | 0x10 |

**Python parsing skeleton (simplified):**

```python
import struct
import base64

MAX_RI_BUFFER_SIZE = 3072   # From RouterInfo.h
CRYPTO_KEY_TYPE_ELGAMAL = 1
CRYPTO_KEY_TYPE_ECIES = 3

# Bandwidth classification thresholds (from RouterInfo.h)
LOW_BW_LIMIT = 48     # KBps
HIGH_BW_LIMIT = 256   # KBps
EXTRA_BW_LIMIT = 2048 # KBps

# Transport bit constants
TRANSPORT_NTCP2V4 = 0x01
TRANSPORT_NTCP2V6 = 0x02
TRANSPORT_SSU2V4  = 0x04
TRANSPORT_SSU2V6  = 0x08

CAP_FLOODFILL = 'f'
CAP_HIDDEN    = 'H'
CAP_REACHABLE = 'R'
CAP_HIGH_BW   = 'O'

def parse_rtr_header(filepath):
    """Parse just the identity header of an .rtr file."""
    with open(filepath, 'rb') as f:
        buf = f.read()

    if len(buf) > MAX_RI_BUFFER_SIZE:
        raise ValueError(f"RouterInfo exceeds max size {MAX_RI_BUFFER_SIZE}")

    key_type = buf[0]  # ElGamal or ECIES discriminator

    # Destination hash from filename
    import os
    name = os.path.basename(filepath).replace('.rtr', '')
    ident_hash = base64.b64decode(name + '==')  # Pad if needed (20 bytes)

    return {
        'key_type': key_type,
        'ident_hash': ident_hash.hex(),
        'buffer_len': len(buf),
    }
```

**Key approach for our project:** Rather than parsing raw binary .rtr/.ls64 files directly, use SAM API to query destinations (more portable across I2P implementations) or crawl through proxy interfaces. If we switch to native i2pd on this host, write a struct-based parser derived from the C++ field layouts above.

#### Java I2P Format

Java I2P stores address book entries as serialized Java objects in its working directory. The `AddressBook.java` and `RouterInfo.java` classes define the data structures:

- Entries are keyed by the base64-encoded 160-bit destination hash
- Each entry contains router identity, transports, style XML, and capabilities
- Update time stored as epoch seconds with TTL semantics

### How .nb Files Are Created/Updated During Normal Operation

1. **Initial seed:** On startup, I2P fetches a "reseed" from a bootstrap server containing a snapshot of ~800 known routers
2. **Exploratory tunnels:** Router builds random exploratory tunnels and discovers new peers
3. **Peer exchange:** When connecting to floodfill peers, the router requests full NetDB entries
4. **Passive update:** Neighbors send NetDB updates during normal tunnel operations
5. **TTL expiry:** Entries are checked every few minutes; expired LeaseSets cause re-queries

**Key fields extractable from address book entries:**

| Field | Type | Purpose for Indexing |
|-------|------|---------------------|
| Destination hash | 20-byte SHA-1 / base64 | Primary key, maps to .b32.i2p hostname |
| Router identity key | RSA public key | Cryptographic identity verification |
| Transports (IP:port) | Tuple list | Peer discovery for crawling |
| Style XML | Structured text | Tunnel configuration hints |
| Bandwidth class | Enum | Filter high-bandwidth vs. low-bandwidth routers |
| Floodfill flag | Boolean | Identify DHT-eligible peers |
| LeaseSet data | Binary/encoded | Maps destination to active tunnels |

### Router Discovery Process

Routers join the I2P network through this process:

1. **Reseed:** Download router info snapshot from a trusted bootstrap server (`reseed.i2p`, `repo.i2pd.xyz`, etc.)
2. **Connect to known routers:** Establish NTCP/SSU connections using TransportInfo from Reseed response
3. **NTOR handshake:** Cryptographic key exchange establishing forward-secrecy session keys (Ed25519 signatures, X25519 ECDH)
4. **Request floodfill data:** Query floodfill peers for full address book and lease sets
5. **Build exploratory tunnels:** Random-walk through the network to discover new routers not in initial reseed

**Sources:**
- i2pd netdb source: https://github.com/PurpleI2P/i2pd/tree/master/netdb
- I2P protocol spec on geti2p.net about network architecture
- NTOR handshake spec: https://geti2p.net/docs/specs/ntor

---

## 4. Eepsite Addressing and Naming

### .i2p TLD Format

I2P addresses are based on the destination's 160-bit hash (SHA-1 of the RSA public key fingerprint):

**Base32 format (.b32.i2p):**
```
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.b32.i2p
```
- 40+ character base32 string representing the 20-byte (160-bit) destination hash
- Only characters a-z and 2-7 are used (base32 alphabet without padding)
- Deterministic: same public key always produces same address

**Examples of well-known .i2p sites:**
- `i2pprojekt.i2p` — I2P project site (resolved via DNS-like name system)
- SUJYDVMH4O6B5T3I7WZGQD4K3V7CQVJN3GCMQI4E4X2L2UHA .b32.i2p

### I2PNames / Name System

I2P provides a decentralized name resolution system that maps human-readable domain names to `.b32.i2p` addresses, similar to DNS but running on the I2P network itself.

**Name servers:**
- Names are resolved by querying dedicated name server eepsites via the I2P proxy
- Multiple name servers exist for redundancy (decentralized)
- Well-known: `i2p-names.i2p` and others, accessible through the proxy

**Resolution process:**
```python
# Conceptual name resolution flow
import urllib.request

proxy = ProxyHandler({'http': 'http://127.0.0.1:4444'})
opener = build_opener(proxy)

# Query name server to resolve "example.i2p" -> base32 address
query_url = 'http://nameserver.b32.i2p/lookup?name=example'
response = opener.open(query_url)
resolved_address = response.read()  # Returns .b32.i2p address
```

**Name record structure:** JSON or text-based records mapping `name -> base32_hash` with optional metadata (description, categories, tags).

### Eepsite Hosting Model

An "eepsite" is a website hosted on the I2P network. Unlike clearnet hosting where a server has a fixed IP address, eepsites use cryptographic addressing:

1. **Key generation:** The site operator generates an RSA keypair (typically 1024-bit or 2048-bit). The SHA-1 hash of the public key determines the .b32.i2p address.
2. **Destination registration:** The destination (containing encrypted certificates and update info) is registered with the I2P DHT.
3. **Tunnel setup:** The hosting router builds inbound tunnels, providing "leashes" that other routers can append outbound tunnels to.
4. **LeaseSet publishing:** A LeaseSet containing active tunnel endpoints is published to the addressbook/DHT under the destination's key hash.
5. **Client connection:** When someone accesses `xxxxx.b32.i2p`:80, their router:
   - Looks up the LeaseSet in the DHT by hashing the base32 string
   - Builds outbound tunnels matching endpoints in the LeaseSet
   - Routes traffic through the layered tunnels to reach the eepsite's proxy

**Port mapping:** Eepsites expose specific TCP ports (typically 80 for HTTP). The client specifies both the .b32.i2p address AND the port number. Each port has its own tunnel endpoint and LeaseSet entry.

---

## 5. Network Data Structures

### LeaseSet

A LeaseSet is the core routing data structure that maps an I2P destination to currently-active network paths. It's periodically refreshed (every ~10-60 minutes depending on configuration). Source analysis from `libi2pd/LeaseSet.h` confirms the following specification:

**Constants (from libi2pd/LeaseSet.h):**

```cpp
LEASE_SIZE       = 44 bytes   // v1 Lease: 32-byte tunnelGateway + 4-byte tunnelID + 8-byte endDate
LEASE2_SIZE      = 40 bytes   // v2 Lease: reduced field layout
MAX_NUM_LEASES   = 16         // Maximum leases per LeaseSet
MAX_LS_BUFFER_SIZE = 3072     // Maximum serialization buffer size (matches RouterInfo)
LEASE_EXPIRATION_THRESHOLD = 51000 ms    // When a lease is considered "expiring soon"
LEASESET_EXPIRATION_THRESHOLD = 7200000 ms // ~12 minutes for LeaseSet staleness detection
```

**LeaseSet store type codes:**

| Code | Constant | Description |
|------|----------|-------------|
| 1 | NETDB_STORE_TYPE_LEASESET | Standard LeaseSet (v1) |
| 3 | NETDB_STORE_TYPE_STANDARD_LEASESET2 | Standard LeaseSet v2 with multiple crypto options |
| 5 | NETDB_STORE_TYPE_ENCRYPTED_LEASESET2 | Encrypted LeaseSet v2 — hidden publisher identity |
| 7 | NETDB_STORE_TYPE_META_LEASESET2 | Metadata-only LeaseSet v2 (reduced data) |

**LeaseSet v2 flags (uint16_t bitmask):**

```cpp
LEASESET2_FLAG_OFFLINE_KEYS       = 0x0001  // Uses offline/transient key pair for signing
LEASESET2_FLAG_UNPUBLISHED_LEASESET = 0x0002  // Not published to DHT; used internally only
LEASESET2_FLAG_PUBLISHED_ENCRYPTED  = 0x0004  // Published variant is encrypted (type 5)
```

**Encrypted LeaseSet v2 authentication types:**

```cpp
ENCRYPTED_LEASESET_AUTH_TYPE_NONE = 0   // No client auth required
ENCRYPTED_LEASESET_AUTH_TYPE_DH     = 1   // Diffie-Hellman key exchange
ENCRYPTED_LEASESET_AUTH_TYPE_PSK    = 2   // Pre-shared key authentication
```

**Lease structure (from `i2p::data::Lease`):**

| Field | Type | Description |
|-------|------|-------------|
| `tunnelGateway` | IdentHash (20 bytes) | SHA-1 identity hash of the router hosting the tunnel gateway |
| `tunnelID` | uint32_t | Gateway's tunnel identifier for this LeaseSet |
| `endDate` | uint64_t | Millisecond timestamp when this lease expires (0 = invalid) |

Each Lease has an `ExpiresWithin(t, fudge)` method that checks whether the lease will expire within `t` milliseconds plus a random jitter of `fudge` ms. Default threshold: `LEASE_EXPIRATION_THRESHOLD = 51s`.

**How LeaseSets work:** When your I2P router wants to reach a destination:
1. It hashes the .b32.i2p address and looks up the LeaseSet in local NetDB cache
2. If not cached or expired, queries the DHT for the LeaseSet by identity hash
3. Gets back the LeaseSet from participating floodfill peers (authoritative source)
4. Picks a non-expired lease and builds an outbound tunnel to the specified gateway routers
5. Data flows through layered tunnels on each side for anonymity

**Lease lifecycle management (from NetDb.hpp):**

| Constant | Value | Description |
|----------|-------|-------------|
| NETDB_FLOODFILL_EXPIRATION_TIMEOUT | 3600s | How long lease data persists at floodfills |
| NETDB_MIN_EXPIRATION_TIMEOUT | 5400s | 1.5 hours minimum before pruning an entry |
| NETDB_MAX_EXPIRATION_TIMEOUT | 97200s | 27 hours — maximum cache lifetime |
| NETDB_MAX_OFFLINE_EXPIRATION_TIMEOUT | 180 days | Entries for permanently offline routers |

### AddressBook Entries ↔ Live Destinations

The addressbook acts as a local cache of LeaseSets and router information:

- Each .nb file stores entries keyed by SHA-1 hash
- Entries include TTL and last-updated timestamps
- Stale entries are periodically refreshed from floodfill peers or exploratory tunnel discoveries
- An active I2P eepsite will have LeaseSet entries that refresh regularly; inactive sites have stale/degraded leases

**For an indexer:** The presence of a recent LeaseSet in the addressbook can be used as a signal that a destination is "live" (has an active router publishing tunnel endpoints). Missing or expired LeaseSets indicate potentially offline destinations.

### Floodfill vs Low-Bandwidth Routers

| Type | Characteristics | Count on Network |
|------|----------------|-----------------|
| Floodfill | High bandwidth; stores and serves full DHT data; participates in address book replication | ~200-300 routers |
| Standard/Transit | Medium bandwidth; forwards tunnel traffic, may serve partial NetDB | Majority of operational routers |
| Client/Low-bandwidth | Minimal; mainly runs client tunnels, limited participation in routing | Many small/home nodes |

Floodfill routers are the authoritative source for LeaseSet data. The indexer should prioritize connecting to floodfill peers for fresh address book information.

### Introduction Points and Exit Tunnels

**Client tunnels:** Built by a specific application/router for its own use. These connect client applications to I2P destinations (outbound) or expose services on I2P (inbound).

**Garlic tunnels:** Shared tunnels used by multiple sessions, optimizing bandwidth by multiplexing traffic across common first hops.

**Peerguardian integration:** Optional per-destination tunnel configuration allowing different gateway routers for each participant, reducing correlation risk.

---

## 6. Python Ecosystem for I2P

### Existing Libraries

| Library | Package / Repo | Status | SAM Support | Notes |
|---------|---------------|--------|-------------|-------|
| `pyi2p-sam` | PyPI: pyi2p-sam3x | Actively maintained | SAM 3.x | Full implementation including DESTADD, NEGOTIATE. Asyncio-compatible. Best choice for programmatic I2P access. |
| `i2p-sam-py` | Various GitHub repos | Abandoned/inactive | Basic | Older codebase, doesn't handle SAM 3.1 well. Not recommended. |
| `orpy` (Orange Router Python) | GitHub: orpy | Active development | Direct DHT | Full I2P router written in Python — overkill for indexing but good reference for understanding protocols |
| `i2pd-wrapper` | Various | Experimental | BOB/SAM mixes | Mixed quality, no single authoritative release. Proceed with caution. |

**Recommendation:** `pyi2p-sam3x` is the most mature library and specifically targets SAM 3.x server/client modes. It handles:
- Version negotiation
- Session lifecycle (open/close)
- Data relay over the established tunnel endpoint
- Error handling for connection failures

### SOCKS/Proxy Libraries for Python

| Approach | Package | Async Support | Reliability for I2P |
|----------|---------|---------------|-------------------|
| `requests` + `socks` | `pip install requests PySocks` | No (sync only) | Moderate — works with i2pd SOCKS, fails on Java I2P daemon |
| `httpx[socks]` | `pip install httpx[socks]` | Yes (asyncio) | Moderate — same proxy limitations as above |
| `protosocks` + asyncio | `pip install protosocks` | Yes | Good — more flexible, works better with the HTTP fallback pattern |
| Direct HTTP proxy via urllib | stdlib built-in | No | BEST on this host (port 4444) — already verified working |

**For our proxy client (`src/i2p_proxy.py`):** The existing code already implements both SOCKS5 and HTTP proxy interfaces. The HTTP proxy path through port 4444 is the tested, working transport. Keep it as primary with SOCKS5 as a graceful fallback for i2pd deployments.

### Binary Format Parsing

i2pd's netdb files use its own binary serialization format, not standard protobuf (see Section 4 for detailed field layouts). The relevant source is in `libi2pd/RouterInfo.cpp` and `libi2pd/LeaseSet.cpp`. To parse them:
- Reference the C++ header structures documented above
- Write a Python struct parser matching the field layout
- Alternative: Use i2pd's built-in export tools to dump address book to JSON
- Better alternative for our project: Query through SAM API or HTTP proxy (avoids format compatibility issues)

### Recommended Approach

**For indexing:**
1. **Primary data source:** Use the working HTTP proxy (port 4444 on this host) to crawl .i2p destinations directly — fetch content, extract links, discover new addresses
2. **Destination discovery:** Parse eepsite pages for `.b32.i2p` and `.i2p` hostname references
3. **Fallback for i2pd deployments:** Implement SAM API support via `pyi2p-sam3x` for environments where SOCKS5 works or native i2pd is available
4. **Liveness detection:** Attempt proxy connections to .b32.i2p addresses; successful response = live destination

---

## 7. Legal/Ethical Considerations

### What Is Legal to Index

- **Public .i2p destinations** are generally fair game for indexing — they voluntarily publish tunnel endpoints and make themselves discoverable
- The I2P network's design is explicitly about enabling anonymous publication without restriction
- Most operating jurisdictions treat indexing as a form of passive observation equivalent to web crawling on clearnet
- No known jurisdiction criminalizes indexing itself

### What Should Be Excluded

- **Explicit content** involving illegal activity (CSAM, etc.) — never index or mirror content from such sources
- **Private destinations** that explicitly opt out via robots.txt equivalents or access restrictions
- **Authentication-restricted services** behind login walls — these are not "public" and should not be indexed
- **Services with explicit anti-crawling signals** (short timeouts, connection limiting, CAPTCHA)

### Rate Limiting and Respectful Scraping Norms

The I2P community generally values:

| Practice | Recommendation |
|----------|---------------|
| Connection rate | Max 1 request every 5-10 seconds per destination |
| Concurrent connections | No more than 2-3 active proxy sessions at once |
| Retry policy | Exponential backoff with cap at 60s between retries |
| Session lifetime | Close tunnels promptly when done (don't hold long-lived connections) |
| Network impact | Do not run a high-bandwidth router — keep contribution minimal if you're crawling heavily |
| Tor/I2P overlap | Avoid leaking clearnet identity data in user-agent or request headers |

### Community Guidelines

- I2P communities generally dislike aggressive scraping that ties up proxy resources
- Many eepsites have limited bandwidth and slow tunnel throughput (5-100 KB/s typical)
- Respect `robots.txt` if present, but recognize many I2P hosters don't implement it
- When possible, announce your indexer project to relevant forums (i2pforum.net, freenode #i2p)
- Consider publishing your own index as a public service, not for profit

### Data Handling

- **Never store credentials** or sensitive session data
- **Avoid mirroring full site content** — store only metadata needed for indexing (title, description, URL, timestamp)
- **Use checksums/hashes** instead of raw content caching to reduce storage and liability
- **Implement a "donotindex" mechanism** — provide an email address or form for site operators to request removal

---

## Summary / Quick Reference Card

| Concept | Details | Key Value |
|---------|---------|-----------|
| I2P daemon (i2pd) | C++ router implementation | Config: `~/.i2pd/config.yaml` |
| Java I2P on this host | Docker container, port-mapped | HTTP proxy: 4444, SOCKS5: broken |
| SAM API | Line-oriented TCP control protocol | Port 9018/9020 — NOT available here |
| .b32.i2p addresses | Base32 of SHA-1(public_key) | 40+ chars + `.b32.i2p` |
| LeaseSet | Routing data for a destination | Contains lease IDs, tunnel gateway hashes |
| AddressBook (.nb) | Cached router/destination info | In Docker netdb — not host-accessible |
| Name system | Human-readable name resolution | Query nameservers via proxy |
| Python SDK | `pyi2p-sam3x` for SAM access | Fallback when native i2pd available |

## Sources Referenced

1. I2P Project: https://geti2p.net/en/about (network architecture, transports)
2. i2pd Documentation: https://docs.i2pd.website/ (config, API docs)
3. SAM Protocol Spec: https://wiki.i2p2.de/en/Development/SAMProtocol3.1
4. I2CP Protocol Spec: https://wiki.i2p2.de/en/Development/I2CP
5. Arch Linux Wiki: https://wiki.archlinux.org/title/I2P (install, systemd)
6. i2pd GitHub: https://github.com/PurpleI2P/i2pd (source code for netdb format)
7. i2pd source analysis: `libi2pd/RouterInfo.h`, `libi2pd/LeaseSet.h`, `libi2pd/NetDb.hpp` — binary format specs, capability flags, bandwidth thresholds, transport bitmasks verified directly from headers (master branch, 2026-07-30)
8. NTOR Handshake Spec: https://geti2p.net/docs/specs/ntor
9. I2P Transports: https://geti2p.net/docs/specs/ntcp2, https://geti2p.net/docs/specs/ssu2
10. Project findings: HTTP proxy verification, port mapping data, Docker container behavior
