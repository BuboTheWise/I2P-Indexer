#!/usr/bin/env bash
# I2P Indexer — Layered Pipeline
# Place in /home/stefan/Projects/I2P-Indexer/pipeline.sh
# Run from project root, or set the path explicitly.

set -euo pipefail

PROJECT="/home/stefan/Projects/I2P-Indexer"
cd "$PROJECT"

# Activate the project venv if it exists (needed for cron/manual runs)
if [ -f "$PROJECT/.venv/bin/python3" ]; then
    PYTHON="$PROJECT/.venv/bin/python3"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON="python3"
else
    PYTHON="/usr/bin/python3"
fi
DB="./indexer.db"

LOGDIR="$PROJECT/logs"
mkdir -p "$LOGDIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGDIR/pipeline.log"
}

###############################################################################
# LAYER 1 — PROBE SWEEP (network reachability)
# Reaches out to .i2p destinations via the local proxy, records status/headers/
# body_length/find_links in the discoveries table.
###############################################################################

probe_all() {
    log "LAYER 1: Full sweep of all targets"
    $PYTHON probe_sweep.py --sweep-filter all --db "$DB" --delay 8 \
        >> "$LOGDIR/probe_all.log" 2>&1
}

probe_reachable() {
    log "LAYER 1: Daily reachable-sites health check"
    $PYTHON probe_sweep.py --sweep-filter reachable_only --db "$DB" --delay 3 \
        >> "$LOGDIR/probe_reachable.log" 2>&1
}

probe_new_imports() {
    log "LAYER 1: Load addressbook, probe only never_probed entries"
    $PYTHON probe_sweep.py --load-address-book --sweep-filter never_probed \
        --db "$DB" >> "$LOGDIR/probe_new.log" 2>&1
}

probe_stale() {
    local HOURS="${1:-24}"
    log "LAYER 1: Stale catch-up (>$HOURS hours)"
    $PYTHON probe_sweep.py --sweep-filter stale --min-age-hours "$HOURS" \
        --db "$DB" >> "$LOGDIR/probe_stale.log" 2>&1
}

###############################################################################
# LAYER 2 — TRANSLATE SUMMARIES (non-English → English via Ollama)
# Done BEFORE deep analysis so the LLM gets English input for better results.
###############################################################################

translate_summaries() {
    log "LAYER 2: Translate non-English summaries"
    $PYTHON translate_summaries.py --ollama-url http://localhost:11434 \
        --limit 50 >> "$LOGDIR/translate.log" 2>&1
}

###############################################################################
# LAYER 3 — DEEP ANALYSIS (Ollama JSON for content understanding)
# Sends page body through local LLM → extracts site_type, purpose,
# sections, interest_score, interest_reasons into discoveries.deep_analysis.
###############################################################################

analyze_reachable() {
    log "LAYER 3: Deep analysis of reachable sites (never analyzed or stale)"
    $PYTHON src/deep_analysis.py --mode reachable --limit 50 \
        >> "$LOGDIR/analyze_reachable.log" 2>&1
}

analyze_stale() {
    log "LAYER 3: Re-analyze old entries with updated prompt fields"
    $PYTHON src/deep_analysis.py --mode stale --limit 50 \
        >> "$LOGDIR/analyze_stale.log" 2>&1
}

###############################################################################
# LAYER 4 — EXTRACTOR GENERATION (for flagged/needs_review sites)
# Probes flagged destinations and generates BaseExtractor plugin skeletons.
# Use --dry-run first to preview, then --confirm to write files.
###############################################################################

generate_extractors() {
    local CONFIRM="${1:-dry-run}"
    if [ "$CONFIRM" = "dry" ]; then
        log "LAYER 4: Dry-run extractor generation for flagged sites"
        $PYTHON src/analyzer.py all-flagged >> "$LOGDIR/extractor_gen.log" 2>&1
    else
        log "LAYER 4: Write extractors to disk and clear flags"
        $PYTHON src/analyzer.py all-flagged --confirm \
            >> "$LOGDIR/extractor_gen_confirm.log" 2>&1
    fi
}

###############################################################################
# LAYER 5 — EXPORT (generate browse UI / address book files)
# Creates HTML + TXT from the address_book view, including interest scores.
###############################################################################

export_ui() {
    local OUTDIR="${1:-website}"
    log "LAYER 5: Export address book with interest scores to $OUTDIR/"
    $PYTHON probe_sweep.py export --output-dir "$OUTDIR" --db "$DB" \
        >> "$LOGDIR/export.log" 2>&1
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
    export_ui website
    log "========================================"
    log "FULL PIPELINE COMPLETE"
    log "========================================"
}

run_daily_refresh() {
    log "DAILY REFRESH: reachable sweep + translate + quick analysis pass"
    probe_reachable
    translate_summaries
    analyze_reachable
    export_ui website
}

run_stale_catchup() {
    log "STALE CATCHUP: re-probe old sites + translate + re-analyze with new prompt fields"
    probe_stale 24
    translate_summaries
    analyze_stale
}

###############################################################################
# CLI interface — pass action name as first arg
###############################################################################

case "${1:-help}" in
    full)       run_full_pipeline ;;
    daily)      run_daily_refresh ;;
    stale)      run_stale_catchup ;;
    probe-all)  probe_all ;;
    probe-reach) probe_reachable ;;
    probe-new)  probe_new_imports ;;
    probe-stale) probe_stale "${2:-24}" ;;
    analyze)    analyze_reachable ;;
    re-analyze) analyze_stale ;;
    translate)  translate_summaries ;;
    extractors-dry) generate_extractors dry ;;
    extractors) generate_extractors write ;;
    export)     export_ui "${2:-website}" ;;
    help|*)
        cat <<EOF
Usage: $0 <action> [options]

Actions (layered pipeline):
  full          Run all layers (probe → translate → analyze → extract → export)
  daily         Reachable check + translate + analysis + export (daily cron target)
  stale         Re-probe old sites + translate + re-analyze with new prompt fields

Layer commands:
  probe-all     L1 — Full sweep of all targets
  probe-reach   L1 — Reachable-only health check
  probe-new     L1 — Load addressbook, probe never_probed entries
  probe-stale [H] L1 — Stale catch-up (default 24h)

  analyze       L3 — Deep analysis of reachable/never-analyzed sites
  re-analyze    L3 — Re-analyze old entries with updated prompt fields
  translate     L2 — Translate non-English summaries via Ollama

  extractors-dry L4 — Preview extractor generation for flagged sites
  extractors      L4 — Write extractors and clear flags

  export [DIR]    L5 — Export address book HTML/TXT to DIR (default: website)

Schedule with system cron or hermes kanban:

  System cron examples:
    # Daily reachable refresh at 04:00
    0 4 * * * /home/stefan/Projects/I2P-Indexer/pipeline.sh daily
    # Weekly full pipeline on Sunday 02:00
    0 2 * * 0 /home/stefan/Projects/I2P-Indexer/pipeline.sh full
    # Stale catch-up every 6 hours
    0 */6 * * * /home/stefan/Projects/I2P-Indexer/pipeline.sh stale

  Or queue via kanban (runs on cthugha):
    hermes kanban create --assignee cthugha \
      --body 'bash pipeline.sh daily' "Daily I2P refresh"
EOF
        ;;
esac
