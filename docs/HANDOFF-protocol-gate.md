## Protocol Gate — Handoff for Bubo

**Repos:** `BuboTheWise/I2P-Indexer`
**Branch:** `feat/protocol-gate` (from `master` at `ec851ec` = 0.4.11)
**Local commit (not yet pushed):** `2e6fc26`
**Test status:** 245 passed, 8 skipped (no new regressions vs. baseline)

---

### What's Done (local, NOT pushed)

Full protocol-gate design, ~400 lines across 2 source files + 2 test files:

**`src/i2p_proxy.py`** (+162):
- `_PROTOCOL_SIGNATURES` and `_PROTOCOL_PATTERNS_RE` — data-driven signature tables (HTTP, SMTP/NNTP, IRC gateway, BOB bridge, BitTorrent tracker)
- `_fingerprint_protocol(banner: bytes) -> str` — fixed-prefix fast path + regex + heuristics; empty banner → `"closed"` (was misguessed as `"smtp/tls"`)
- `ServiceClassification` frozen dataclass: `protocol`, `confidence` (0.0–1.0), `raw_banner`, `service_type`, `is_non_http` property
- `classify_service(banner: bytes)` → `ServiceClassification`
- `_SERVICE_TYPE_LABELS` — human-readable display labels

**`src/integration.py`** (+215):
- `services` table DDL: `PRIMARY KEY(host, port)`, first_seen/last_seen, protocol, service_type, banner blob, status
- `DiscoveryDB.record_service()` — UPSERT keyed on `(host, port)`; preserves `first_seen`
- `DiscoveryDB.get_service()` — read by `(host, port)`
- `probe_destination(service_gate: bool = False, port: int = 0)` — opt-in gate:
  1. Reads TCP banner first
  2. Classifies via `classify_service()`
  3. If `is_non_http` → writes services row, returns early (skips HTTP fetch + extractors)
  4. Gate failure → falls through to normal b32/DNS path
- `GATE_CONFIDENCE_THRESHOLD = 0.85`, `DEFAULT_GATE_PORT = 443`
- `DiscoveryResult` gained `service_type`, `service_protocol`, `gate_applied`, `gate_confidence`

**Tests:**
- `tests/test_protocol_gate.py` (new, 324 lines, 22 tests) — classification, DB UPSERT, gate-fires/falls-through/off behavior
- `tests/test_protocol_fingerprinting.py` — `test_empty_banner` fixed: `"smtp/tls"` → `"closed"`

---

### What Bubo Needs to Do

1. **Run full test suite** (verify no new regressions):
   ```bash
   .venv/bin/python3 -m pytest --tb=short -q
   ```
   Pre-existing failures on master (already verified): 5 translation tests (Ollama offline) + 1 smoke test (live I2P peer) — NOT gate regressions.

2. **Version bump `0.4.11` → `0.4.12`:**
   ```bash
   sed -i 's/VERSION="0.4.11"/VERSION="0.4.12"/' pipeline.sh
   sed -i 's/version = "0.4.11"/version = "0.4.12"/' pyproject.toml
   sed -i 's/__version__ = "0.4.11"/__version__ = "0.4.12"/' src/__init__.py
   ```

3. **Commit version bump:**
   ```bash
   git add pipeline.sh pyproject.toml src/__init__.py
   git commit -m "chore(0.4.12): version bump — protocol gate"
   ```

4. **Merge to master + tag + push + delete branch:**
   ```bash
   git checkout master
   git merge feat/protocol-gate --no-ff
   git tag v0.4.12
   git push origin master --tags
   git push origin :feat/protocol-gate
   git branch -d feat/protocol-gate
   ```

---

### Key Design Decisions

- **`service_gate` defaults to `False`** — fully backward compatible; existing callers unaffected
- **Confidence threshold 0.85** — high-confidence match ≥ 0.90 fires gate; ambiguous (0.5) falls through. Asymmetric: a false "non-HTTP" masks a real web site, so the bar is deliberately high
- **Empty banner = `closed`** — port rejected/ignored TCP, not SMTP-over-TLS
- **No `.strip()` on banner** — IRC protocol uses leading space (`" :Welcome…"`) as protocol marker
- **PK `(host, port)`** — uniquely identifies a service endpoint (same host, different ports can run different protocols)

---

### Local files for reference

All changes are on `/home/stefan/Projects/I2P-Indexer` in the `feat/protocol-gate` branch. Full implementation is in:
- `src/i2p_proxy.py` — classification (lines 650–790ish)
- `src/integration.py` — DB methods + gate wiring (see `grep -n 'def record_service\|def get_service\|service_gate\|GATE_CONFIDENCE' src/integration.py`)
- `tests/test_protocol_gate.py` — full test file
- `docs/HANDOFF-protocol-gate.md` — this document

Tarball also available at `/tmp/protocol-gate-handoff.tgz` if you need it.
