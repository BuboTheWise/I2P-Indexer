# Smoke Test Usage and Maintenance

## What This Is

A mechanical verification tool that exercises the full probe pipeline — fetch through I2P proxy, run extractors, classify content, and store results in SQLite. It confirms each stage is functional end-to-end against a small set of known `.i2p` destinations.

**This is NOT an uptime guarantee service.** The targets are historically reachable but I2P eepsites go offline without notice. A passing run proves the pipeline works; a failing run may mean the target went dark, not that your code is broken.

## Prerequisites

- I2P daemon running (Docker container on this host)
- Proxy configured via `I2PConfig` in `src/config.py` (default: `localhost:4444` HTTP)
- Virtual environment active with project dependencies installed

## Running the Smoke Test

From the project root:

```bash
# Default run — all targets, 120s timeout per target
python -m src.smoke_test

# Shorter deadline if I2P is responding slowly
python -m src.smoke_test --timeout 60

# Probe and extract only — skip writing to the database
python -m src.smoke_test --dry-run

# Machine-readable JSON report to stdout (CI-friendly)
python -m src.smoke_test --json

# Debug-level logging for troubleshooting pipeline failures
python -m src.smoke_test -v

# Custom target file
python -m src.smoke_test --targets /path/to/my_targets.json
```

## Interpreting Output

### Summary Table

After probing all targets, a summary table shows each target with:

- **PASS/FAIL** — Overall verdict from the validation gate
- **status** — HTTP status code returned (or `(none)` on connection failure)
- **bytes** — Response body size in bytes
- **type** — Content type assigned by the extractor registry
- **Check indicators** — Six named checks with pass/fail symbols:

| Check | Meaning |
|---|---|
| `probe_ok` | Probe stage succeeded, HTTP response received |
| `status_in_range` | Status is 1xx–4xx (not 5xx or connection-rejected) |
| `body_sufficient` | Body >= 128 bytes (filters out error pages / empty responses) |
| `content_classified` | Extractor assigned a non-empty content type |
| `summary_present` | At least one summary line extracted from body |
| `no_fatal_error` | No stage produced an unhandled exception |

A target only PASSES when all six checks pass.

### Per-Target Failure Reasons

When a target fails, indented lines under it explain which checks failed:
```
[FAIL] some_target.i2p           status=0    bytes=0      type=(none)
       -t Probe stage failed — network or proxy error
       -t HTTP 0 outside acceptable range (1xx-4xx)
       -t Body too small (0B < 128B minimum)
```

### Exit Codes

| Code | Label | Meaning |
|---|---|---|
| `0` | ALL PASSED | Every target passed validation |
| `1` | PROBE FAILURE | One or more targets failed at the network/proxy level |
| `2` | EXTRACTION/CLASSIFICATION FAILURE | Pipeline reached the target but extractors failed |
| `3` | STORAGE FAILURE | Database write failed (usually DB locked or missing) |
| `4` | CONFIGURATION ERROR | Targets file missing, empty, or malformed JSON |
| `5` | PROXY UNREACHABLE | Pre-flight health check itself could not reach the proxy |

## Maintaining Target Lists

### Location

Targets live in `tests/smoke_targets.json`. They are test fixtures, not application code — never hardcode them into source files.

### Target Schema

Each target is a JSON object:
```json
{
  "name": "Display Name",
  "url": "http://something.i2p/",
  "expected_content_type": "text/html",
  "description": "What this site does.",
  "notes": "Known quirks or behavior."
}
```

Required fields: `name`, `url`. Everything else is informational.

### When to Refresh

**Refresh monthly.** The targets file has `_last_refresh` and `_refresh_frequency` metadata fields at the top — update these when you modify targets. Signs you need a refresh:

1. **Same target repeatedly fails** — 3 consecutive runs with probe failures on the same destination means it's likely offline.
2. **Exit code 1 (PROBE FAILURE) on every run** — If the only problem is one or two dead targets, replace them. If ALL targets fail, check your I2P proxy first before blaming targets.
3. **Content type changes** — If an extractor stops matching because a site changed layout, update `expected_content_type` (informational, doesn't affect validation).

### How to Add a New Target

1. Find a `.i2p` destination you want to test against.
2. Verify it responds HTTP >= 200 through your I2P proxy:
   ```bash
   python -c "from src.i2p_proxy import fetch_i2p; r = fetch_i2p('http://new-target.i2p/', via='http-proxy'); print(r.status, len(r.body))"
   ```
3. Add it to the `targets` array in `tests/smoke_targets.json`.
4. Run the smoke test with `-v` to confirm it passes all six validation checks.

### How to Remove a Dead Target

1. Comment out or remove the target from `tests/smoke_targets.json`.
2. Update `_last_refresh` to today's date.

Keep at least 3 targets in the file — fewer makes it unreliable as a pipeline regression detector.

## Troubleshooting

### Exit code 5 (PROXY UNREACHABLE)

Your I2P daemon isn't responding on the configured HTTP proxy port. Check:
- Docker container is running: `docker ps | grep i2p`
- Proxy port matches `I2PConfig` defaults or your custom config
- Firewall allows localhost traffic to the proxy port

### Exit code 1 but proxy is healthy

Individual targets went offline (normal for I2P — destinations are ephemeral). Replace them per the maintenance section above. This does not indicate a pipeline bug.

### Exit code 2 (EXTRACTION FAILURE)

The probe succeeded but extractors returned empty results. Possible causes:
- Site content changed and no pattern matched
- Response body is binary/non-text
- HTML structure doesn't match any extractor heuristic

Run with `--json -v` to see the raw body length and extractor details, then either update the target or add a new extractor if the site has permanent value.

### Exit code 3 (STORAGE FAILURE)

The SQLite discovery DB is locked, read-only, or missing its directory. Use `--dry-run` to skip storage temporarily while you investigate.

## CI Integration

For automated pipelines, use:
```bash
python -m src.smoke_test --json --dry-run --timeout 60
```

- `--json` outputs structured JSON parseable by CI reporters
- `--dry-run` avoids polluting a shared database with transient probe data
- `--timeout 60` prevents CI from hanging on slow I2P connections

The exit code tells the CI system whether to green or red. A non-zero exit does NOT necessarily mean broken code — it may just mean targets changed, which is normal in I2P land.
