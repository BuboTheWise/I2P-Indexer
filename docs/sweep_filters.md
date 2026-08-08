# I2P Indexer — Sweep Filter Reference and Cron Patterns

This document covers how to use `probe_sweep.py` sweep filters for recurring automation (cron jobs, manual workflows, etc.).

---

## TL;DR Quick Commands

| What you want | Command |
|---|---|
| Full baseline sweep (weekly) | `python3 probe_sweep.py --sweep-filter all` |
| Daily reachable-sites check | `python3 probe_sweep.py --sweep-filter reachable_only` |
| Re-probe stale targets (> 24h old) | `python3 probe_sweep.py --sweep-filter stale --min-age-hours 24` |
| First pass on brand-new imports | `python3 probe_sweep.py --sweep-filter never_probed` |

---

## Sweep Filter Modes

### `all` (default)

Probe **every** target in the database, regardless of state. This is the full baseline sweep that touches all entries — reachable, unreachable, and never-probed alike.

```bash
python3 probe_sweep.py --sweep-filter all
```

Since this probes everything, it's the slowest mode but ensures nothing is missed during a complete refresh. Combine with `--delay 8` for gentler network usage on I2P.

**When to use:** Weekly baseline sweeps, after major database changes, or when you want a complete picture of reachability across all known destinations.

### `reachable_only`

Probe **only** targets that have at least one reachable discovery record in the database. Sites that were never reachable are skipped entirely.

```bash
python3 probe_sweep.py --sweep-filter reachable_only
```

This is fast because it avoids trying again on sites already confirmed dead or unreachable. It's ideal for health monitoring of known-live destinations, since you care mostly about whether previously-working sites are still working.

**When to use:** Daily/periodic health checks on known-live I2P eepsites. Use with lower `--delay` (e.g., 3s) since the set is usually smaller and all targets tend to be responsive.

### `never_probed`

Probe **only** targets where `last_probed_at == 0`, i.e., entries that have never been probed yet. These are freshly imported destinations from an addressbook load or SUSI export that haven't been touched by any sweep run.

```bash
python3 probe_sweep.py --sweep-filter never_probed
```

After loading new entries with `--load-address-book` or `--import-export`, this mode efficiently probes just the delta — new imports only — without wasting time re-contacting targets already checked in previous sweeps.

**When to use:** Immediately after importing a new addressbook, SUSI export, or linked-site crawl results. Run once after the import; subsequent runs will find nothing matching (since those targets were probed).

### `stale`

Probe targets whose **last successful probe is older than `min_age_hours`** ago. Default threshold is 24 hours. Uses parameterized SQL (`?`) so it is injection-safe regardless of the value passed via CLI.

```bash
# Default: re-probe anything not checked in >24h
python3 probe_sweep.py --sweep-filter stale

# Custom threshold: re-probe anything not checked in >6h
python3 probe_sweep.py --sweep-filter stale --min-age-hours 6

# Very conservative: only if data is >1 week old
python3 probe_sweep.py --sweep-filter stale --min-age-hours 168
```

The stale filter uses `last_probed_at` timestamps stored as Unix epoch floats. A cutoff timestamp is calculated at query time (`time.time() - min_age_hours * 3600`), so the window is always relative to "now."

**When to use:** Catch-up sweeps — for example, every hour re-probe anything that hasn't been checked in the last 24h. This keeps stale data fresh without touching recently-verified sites. Also useful after network downtime when you want to verify previously-reachable sites are still live but don't need to recheck ones verified an hour ago.

---

## Target Queue Prioritisation

Within any filtered set, targets are ordered by priority:

1. **Previously reachable first** — highest chance of a successful probe, so network bandwidth is used efficiently.
2. **Valid 40-char SHA-1 hash present** — b32 direct-key probing works for these even if DNS resolution fails.
3. **Oldest `last_probed_at` first** — within each tier, targets not seen recently are probed before more recently-checked ones.

This ordering applies regardless of which filter mode is active. The filter reduces the candidate set; priority determines the order within that set.

---

## Recommended Cron Schedules

These schedules assume a reasonably stable I2P connection and moderate database size (~500-3000 targets). Adjust `--delay` based on your network conditions and database size.

### Minimal (two jobs)

```cron
# Sunday 02:00 — weekly full baseline (catches everything new or changed)
0 2 * * 0 cd /path/to/I2P-Indexer && python3 probe_sweep.py --sweep-filter all --delay 8

# Daily 04:00 — reachable site health check (fast, skips dead entries)
0 4 * * * cd /path/to/I2P-Indexer && python3 probe_sweep.py --sweep-filter reachable_only --delay 3
```

This gives a full sweep once per week and daily monitoring of live sites. The weekly baseline catches any new imports that haven't been probed yet and stale entries missed by the daily run.

### Aggressive (three jobs)

```cron
# Sunday 02:00 — weekly full baseline
0 2 * * 0 cd /path/to/I2P-Indexer && python3 probe_sweep.py --sweep-filter all --delay 8

# Daily 04:00 — reachable refresh
0 4 * * * cd /path/to/I2P-Indexer && python3 probe_sweep.py --sweep-filter reachable_only --delay 3

# Hourly — stale catch-up (any target not probed in 24h)
0 * * * * cd /path/to/I2P-Indexer && python3 probe_sweep.py --sweep-filter stale --min-age-hours 24
```

The hourly stale job fills gaps between the daily and weekly runs. After an addressbook load, newly imported targets that haven't been probed yet will show up in the stale filter (since their `last_probed_at` is effectively 0/epoch, which is always > 24h ago).

### Targeted workflow (manual trigger after import)

```bash
# Step 1: Load new addressbook entries
python3 probe_sweep.py --load-address-book

# Step 2: Probe only the never-seen imports
python3 probe_sweep.py --sweep-filter never_probed

# Step 3: Generate report of current state
python3 probe_sweep.py --report sweep_report.txt
```

---

## Dry Run Before Launching

Use `--dry-run` with any filter to inspect the target set before committing real probes. This helps verify the filter is matching what you expect and gives a head count:

```bash
# See what would be probed (no actual network requests):
python3 probe_sweep.py --dry-run --sweep-filter reachable_only
python3 probe_sweep.py --dry-run --sweep-filter stale --min-age-hours 6
python3 probe_sweep.py --dry-run --sweep-filter never_probed
```

The dry run prints the database path, target count, and up to 20 entries with their DNS name or hash prefix. If more than 20 match, it shows `... and N more`.

---

## Combining with Other Flags

Sweep filters work with all existing probe_sweep.py options:

| Flag | Combined example |
|---|---|
| `--count N` | `python3 probe_sweep.py --sweep-filter stale --count 50` (probe max 50 stale targets) |
| `--delay S` | `python3 probe_sweep.py --sweep-filter reachable_only --delay 2` (faster probing of live sites) |
| `--report PATH` | `python3 probe_sweep.py --sweep-filter reachable_only --report report.md` (probe + generate report) |
| `--show-book` | `python3 probe_sweep.py --sweep-filter all --show-book` (full sweep + print address book) |
| `--probe-timeout S` | `python3 probe_sweep.py --sweep-filter reachable_only --probe-timeout 60` (shorter timeout for health checks) |
| `--crawl-depth N` | `python3 probe_sweep.py --sweep-filter all --crawl-depth 2` (auto-crawl linked sites up to depth 2) |
| `--max-new-targets N` | `python3 probe_sweep.py --crawl-depth 2 --max-new-targets 25` (limit auto-crawl to 25 new discoveries) |
| `--dry-run` | See dry run section above |

---

### How `--crawl-depth` interacts with `--count` and `--delay`

These three flags control different aspects of the same sweep run:

- **`--count N`** limits how many targets from the queue are probed in this session.
  When auto-crawl discovers new `.i2p` links, those become additional queue entries subject to the count limit.
  For example, `--count 50 --crawl-depth 2` probes up to 50 targets total — if the first sweep batch discovers 30 new
  linked sites, only 20 of those can be probed before hitting `--count`.

- **`--delay S`** sets seconds between probes. When combined with auto-crawl, this delay applies to ALL probes including
  the ones triggered by discovered links. Use a higher `--delay` (e.g., 8s) when running deeper crawls to be gentler
  on I2P network bandwidth.

- **`--crawl-depth N`** controls recursion depth: `0` = no auto-crawl, `1` = probe direct links only,
  `2+` = recursive discovery at each depth level. Deeper crawls benefit from higher `--delay` and lower `--count`
  to avoid overwhelming the I2P network.

Example combinations:

```bash
# Shallow crawl — just discover directly-linked sites (default):
python3 probe_sweep.py --crawl-depth 1 --max-new-targets 50

# Deep crawl with controlled pace:
python3 probe_sweep.py --crawl-depth 3 --delay 8 --count 200 --max-new-targets 75

# Dry run to see how many targets would be touched before committing:
python3 probe_sweep.py --dry-run --crawl-depth 2 --max-new-targets 100
```

---

## Implementation Notes

- **SQL injection safety:** The `stale` filter uses parameterized queries (`?`) — the `min_age_hours` value is converted to a Unix timestamp cutoff in Python and passed as a bound parameter. No string interpolation of user input into SQL.
- **File being edited:** `/home/stefan/Projects/I2P-Indexer/probe_sweep.py` (module-level docstring)
- **Source truth for filter logic:** `src/integration.py` — `DiscoveryDB.get_targets()` at line ~1315, `discover_addresses()` at line ~1726
