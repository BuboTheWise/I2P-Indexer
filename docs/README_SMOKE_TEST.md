# Smoke Test — Target Refresh Protocol

## Overview

`tests/smoke_targets.json` contains a curated list of `.i2p` destinations used to smoke-test the full probe → extract → classify → store pipeline without hitting production databases or external network services beyond the I2P proxy.

## Why targets need refreshing

I2P eepsites are ephemeral by design. Destinations go offline, rotate keys, or change addresses without notice. A target that worked last month may be unreachable today. Running smoke tests against dead targets produces false failures and wastes CI time.

The file tracks its own freshness via `_last_refresh` (date string) and `_refresh_frequency` ("monthly").

## Refresh cadence

**Monthly recommended.** The staleness threshold is 30 days. When the file hasn't been updated in 30+ days, a warning fires:

| Trigger | Where it runs | Behavior |
|---------|--------------|----------|
| `python scripts/check_smoke_staleness.py` | CLI / CI step | Exit code 3 (warning) when stale |
| `.githooks/pre-push` | Git pre-push hook | Prints warning (non-blocking) |

## Refresh procedure

1. **Run the staleness check:**
   ```bash
   python scripts/check_smoke_staleness.py
   ```

2. **Probe each target through the I2P proxy.** The simplest way is to use the smoke test itself:
   ```bash
   python -m src.smoke_test --dry-run --timeout 90
   ```
   This fetches each target and prints PASS/FAIL per stage. Targets that fail probe are candidates for replacement.

3. **Replace dead targets.** When a destination is unreachable (HTTP 502 timeout, or HTTPError 400+), find an active `.i2p` address from:
   - The `probe_sweep.py` known-good list
   - `scripts/indexer.db` or `data/i2p_indexer.db` reachable targets
   - Well-known communities (I2P-Planet, I2C)

4. **Update the file with fresh metadata:**
   ```json
   {
     "_last_refresh": "2026-09-07",
     ...
   }
   ```

5. **Verify the pipeline still works end-to-end:**
   ```bash
   python -m src.smoke_test --timeout 120
   pytest tests/test_smoke_test.py
   ```

## Schema

Each target in `"targets"` array:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Human-readable label (used in reports) |
| `url` | string | The `.i2p` URL to probe (required) |
| `expected_content_type` | string | Content type bucket the extractor should detect |
| `description` | string | One-line description for human context |
| `proxy_requirement` | string | Usually "http-proxy" |
| `proxy_default_port` | int | Port for the I2P HTTP proxy (default 4444) |
| `notes` | string | Operational notes — uptime history, infrastructure correlation |

## Staleness check exit codes

| Code | Meaning |
|------|---------|
| 0 | Fresh (within threshold) |
| 1 | File missing |
| 2 | Malformed JSON or missing `_last_refresh` |
| 3 | Stale (older than `--stale-days`) |

## Installing the pre-push hook

```bash
# Git config approach:
git config core.hooksPath .githooks

# Or symlink manual approach:
ln -sf ".githooks/pre-push" .git/hooks/pre-push
```

The hook is non-blocking — it prints a warning but does not abort the push.

## CI integration (future)

Add to your CI pipeline:
```yaml
- name: Check smoke targets freshness
  run: python scripts/check_smoke_staleness.py --stale-days 30
```

Currently no GitHub Actions or other CI is configured for this repo, so the primary staleness gate is the CLI script + pre-push hook.
