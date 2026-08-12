#!/usr/bin/env bash
# I2P Indexer — Layered Pipeline
VERSION="0.4.6"
# Edit the variables below, then run:
#   bash pipeline.sh <action>

set -euo pipefail
PROJECT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT"

###############################################################################
# CONFIGURABLES — edit these before scheduling
###############################################################################

# Database path (relative or absolute)
DB="./indexer.db"

# Output directory for the exported website — change to your webroot
OUTPUT_DIR="/root/I2P/webroot"

# Ollama API endpoint (local LM for translation and deep analysis)
OLLAMA_URL="http://localhost:11434"

# Seconds between each probe request during full sweeps
PROBE_DELAY=8

# Seconds between probes for reachable-only health check (faster)
PROBE_REACHABLE_DELAY=3

# Hours threshold for "stale" catch-up (re-probe sites older than this)
STALE_HOURS=24

# Max sites to analyze per deep_analysis run (lower = shorter runs)
ANALYSIS_LIMIT=50

# Max summaries to translate per run (lower = shorter runs)
TRANSLATE_LIMIT=50

# Max targets for reachable-only health check (use 0 or unset for all)
PROBE_REACHABLE_COUNT=20

# Directory for log files
LOGDIR="./logs"

###############################################################################
# INTERNAL — parse arguments, initialize venv and directories
###############################################################################

VERBOSE=false
ACTION="${1:-help}"
for arg in "$@"; do
    [ "$arg" = "-v" ] && VERBOSE=true
done

echo "pipeline.sh v${VERSION}" >&2

if [ -f "$PROJECT/.venv/bin/python3" ]; then
    PYTHON="$PROJECT/.venv/bin/python3"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
else
    PYTHON="/usr/bin/python3"
fi

# Force unbuffered output so verbose streaming works in real time
export PYTHONUNBUFFERED=1

mkdir -p "$LOGDIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGDIR/pipeline.log" >&2
}

# Run a command, writing output to LOGDIR/<logfile>.
# If VERBOSE is set, also stream output live to the terminal.
run_cmd() {
    local logfile="$1"; shift
    if $VERBOSE; then
        echo "[${FUNCNAME[1]}] Streaming to $logfile ..." >&2
        "$@" 2>&1 | stdbuf -oL tee -a "$LOGDIR/$logfile"
        local rc=${PIPESTATUS[0]}
        echo "[${FUNCNAME[1]}] DONE (rc=$rc) — see $LOGDIR/$logfile" >&2
        return $rc
    else
        "$@" >> "$LOGDIR/$logfile" 2>&1
    fi
}

###############################################################################
# LAYER 1 — PROBE SWEEP (network reachability)
###############################################################################

probe_all() {
    local COUNT="${1:-}"
    log "LAYER 1: Full sweep of all targets"
    if [ -n "$COUNT" ] && [ "$COUNT" -gt 0 ]; then
        run_cmd probe_all.log $PYTHON probe_sweep.py --sweep-filter all \
            --db "$DB" --delay "$PROBE_DELAY" --count "$COUNT"
    else
        run_cmd probe_all.log $PYTHON probe_sweep.py --sweep-filter all \
            --db "$DB" --delay "$PROBE_DELAY"
    fi
}

probe_reachable() {
    local COUNT="${1:-$PROBE_REACHABLE_COUNT}"
    # Pre-flight: show target count instantly before network I/O
    local TOTAL
    TOTAL=$($PYTHON -c "import sqlite3; c=sqlite3.connect('$DB'); print(c.execute('select count(*) from address_book where reachable=1').fetchone()[0])" 2>/dev/null || echo "?")
    log "LAYER 1: Reachable-only health check (limit=${COUNT}, ~${TOTAL} reachable in DB)"
    if [ "$COUNT" -gt 0 ] 2>/dev/null; then
        run_cmd probe_reachable.log $PYTHON probe_sweep.py --sweep-filter reachable_only \
            --db "$DB" --delay "$PROBE_REACHABLE_DELAY" --count "$COUNT"
    else
        run_cmd probe_reachable.log $PYTHON probe_sweep.py --sweep-filter reachable_only \
            --db "$DB" --delay "$PROBE_REACHABLE_DELAY"
    fi
}

probe_new_imports() {
    log "LAYER 1: Load addressbook, probe never_probed entries"
    run_cmd probe_new.log $PYTHON probe_sweep.py --load-address-book \
        --sweep-filter never_probed --db "$DB"
}

probe_stale() {
    local HOURS="${1:-$STALE_HOURS}"
    log "LAYER 1: Stale catch-up (>$HOURS hours)"
    run_cmd probe_stale.log $PYTHON probe_sweep.py --sweep-filter stale \
        --min-age-hours "$HOURS" --db "$DB"
}

###############################################################################
# LAYER 2 — TRANSLATE SUMMARIES (non-English → English via Ollama)
###############################################################################

translate_summaries() {
    log "LAYER 2: Translate non-English summaries"
    run_cmd translate.log $PYTHON translate_summaries.py --ollama-url "$OLLAMA_URL" \
        --limit "$TRANSLATE_LIMIT"
}

###############################################################################
# LAYER 3 — DEEP ANALYSIS (Ollama JSON for content understanding)
###############################################################################

analyze_reachable() {
    log "LAYER 3: Deep analysis of reachable sites"
    run_cmd analyze_reachable.log $PYTHON src/deep_analysis.py --mode reachable \
        --limit "$ANALYSIS_LIMIT"
}

analyze_stale() {
    log "LAYER 3: Re-analyze old entries with updated prompt fields"
    run_cmd analyze_stale.log $PYTHON src/deep_analysis.py --mode stale \
        --limit "$ANALYSIS_LIMIT"
}

###############################################################################
# LAYER 4 — EXTRACTOR GENERATION (for flagged/needs_review sites)
###############################################################################

generate_extractors() {
    local CONFIRM="${1:-dry-run}"
    if [ "$CONFIRM" = "dry" ]; then
        log "LAYER 4: Dry-run extractor generation for flagged sites"
        run_cmd extractor_gen.log $PYTHON src/analyzer.py all-flagged
    else
        log "LAYER 4: Write extractors to disk and clear flags"
        run_cmd extractor_gen_confirm.log $PYTHON src/analyzer.py all-flagged --confirm
    fi
}

###############################################################################
# LAYER 5 — EXPORT (generate browse UI / address book files)
###############################################################################

export_ui() {
    local OUTDIR="${1:-$OUTPUT_DIR}"
    log "LAYER 5: Export address book with interest scores to $OUTDIR/"
    run_cmd export.log $PYTHON probe_sweep.py export --output-dir "$OUTDIR" --db "$DB"

    # List what was exported (cp -v style)
    local count=0
    for f in "$OUTDIR"/*; do
        if [ -f "$f" ]; then
            local size
            size=$(wc -c < "$f")
            log "  Exported: $(basename "$f") ($size bytes)"
            count=$((count + 1))
        fi
    done
    log "  ($count file(s) exported to $OUTDIR/)"
}

###############################################################################
# COMBINED PIPELINE RUNS
###############################################################################

run_full_pipeline() {
    log "========================================"
    log "FULL PIPELINE START"
    log "========================================"
    probe_all
    translate_summaries
    analyze_reachable
    generate_extractors dry
    export_ui
    log "========================================"
    log "FULL PIPELINE COMPLETE"
    log "========================================"
}

run_daily_refresh() {
    log "DAILY REFRESH: reachable sweep + translate + analysis + export"
    probe_reachable
    translate_summaries
    analyze_reachable
    export_ui
}

run_stale_catchup() {
    log "STALE CATCHUP: re-probe old sites + translate + re-analyze"
    probe_stale "$STALE_HOURS"
    translate_summaries
    analyze_stale
}

###############################################################################
# CLI interface — pass action name as first arg
###############################################################################

case "$ACTION" in
    full)       run_full_pipeline ;;
    daily)      run_daily_refresh ;;
    stale)      run_stale_catchup ;;
    probe-all)  probe_all ;;
    probe-reach) probe_reachable ;;
    probe-new)  probe_new_imports ;;
    probe-stale) probe_stale "${2:-$STALE_HOURS}" ;;
    analyze)    analyze_reachable ;;
    re-analyze) analyze_stale ;;
    translate)  translate_summaries ;;
    extractors-dry) generate_extractors dry ;;
    extractors) generate_extractors write ;;
    export)     export_ui "${2:-$OUTPUT_DIR}" ;;
    help|*)
        echo "I2P Indexer Pipeline v${VERSION} — Layered Cron Orchestrator"
        cat <<EOF

Usage: $0 <action> [options] [-v]

Actions (layered pipeline):
  full          Run all layers (probe → translate → analyze → extract → export)
  daily         Reachable check + translate + analysis + export (daily cron target)
  stale         Re-probe old sites + translate + re-analyze with new prompt fields

Layer commands:
  probe-all     L1 — Full sweep of all targets
  probe-reach   L1 — Reachable-only health check
  probe-new     L1 — Load addressbook, probe never_probed entries
  probe-stale [H] L1 — Stale catch-up (default $STALE_HOURS h)

  analyze       L3 — Deep analysis of reachable/never-analyzed sites
  re-analyze    L3 — Re-analyze old entries with updated prompt fields
  translate     L2 — Translate non-English summaries via Ollama

  extractors-dry L4 — Preview extractor generation for flagged sites
  extractors      L4 — Write extractors and clear flags

  export [DIR]    L5 — Export address book HTML/TXT to DIR (default: \$OUTPUT_DIR)

Schedule with system cron or hermes kanban:

  System cron examples (adjust path):
    0 4 * * * /path/to/I2P-Indexer/pipeline.sh daily
    0 2 * * 0 /path/to/I2P-Indexer/pipeline.sh full
    0 */6 * * * /path/to/I2P-Indexer/pipeline.sh stale

  Or queue via kanban (runs on your agent profile):
    hermes kanban create --assignee '<agent-profile>' \
      --body 'bash pipeline.sh daily' "Daily I2P refresh"
EOF
        ;;
esac
