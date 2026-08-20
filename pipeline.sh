1|#!/usr/bin/env bash
2|# I2P Indexer — Layered Pipeline
3|VERSION="0.4.6"
4|# Edit the variables below, then run:
5|#   bash pipeline.sh <action>
6|
7|set -euo pipefail
8|PROJECT="$(cd "$(dirname "$0")" && pwd)"
9|cd "$PROJECT"
10|
11|###############################################################################
12|# CONFIGURABLES — edit these before scheduling
13|###############################################################################
14|
15|# Database path (relative or absolute)
16|DB="./indexer.db"
17|
18|# Output directory for the exported website — change to your webroot
19|OUTPUT_DIR="/root/I2P/webroot"
20|
21|###############################################################################
22|# PER-FEATURE AI CONFIGURATION
23|#
24|#   Each pipeline layer that talks to an LLM backend gets its own endpoint URL
25|#   and model.  Completely independent — no sharing between features.
26|#   Override any of these via environment variables before calling pipeline.sh,
27|#   or source a .env file:
28|#
29|#     export TRANSLATION_URL="http://remote-ollama:11434"      # probe-sweep translations
30|#     export TRANSLATION_MODEL="mistral:7b"                    # translation model
31|#     export ANALYSIS_URL="http://local-ollama:11434"          # deep analysis scoring  
32|#     export ANALYSIS_MODEL="RogerBen/HY-MT2-1.8B:latest"     # analysis model
33|#     export SUMMARY_URL="http://remote-ollama:11434"         # batch summary translation
34|#     export SUMMARY_MODEL="llama3.2"                          # summary model
35|#
36|###############################################################################
37|
38|# Feature 1: Probe-Sweep Translation — endpoint and model for real-time translations
39|TRANSLATION_URL="${TRANSLATION_URL:-http://localhost:11434}"
40|TRANSLATION_MODEL="${TRANSLATION_MODEL:-RogerBen/HY-MT2-1.8B:latest}"
41|
42|# Feature 2: Deep Analysis — endpoint and model for site classification/scoring
43|ANALYSIS_URL="${ANALYSIS_URL:-http://localhost:11434}"
44|ANALYSIS_MODEL="${ANALYSIS_MODEL:-RogerBen/HY-MT2-1.8B:latest}"
45|
46|# Feature 3: Summary Translation (Batch) — endpoint and model for Layer 2 pass
47|SUMMARY_URL="${SUMMARY_URL:-http://localhost:11434}"
48|SUMMARY_MODEL="${SUMMARY_MODEL:-RogerBen/HY-MT2-1.8B:latest}"
49|
50|# LLM-powered extractor generation (OPTIONAL — defaults disabled)
51|#
52|# When enabled, the analyzer sends fingerprint data + HTML sample to an
53|# Ollama-compatible endpoint and uses the returned Python code instead of
54|# the heuristic template. This produces far better extractors but REQUIRES
55|# a code-capable model.
56|#
57|# MODEL REQUIREMENTS:
58|#   - The model MUST be able to generate valid Python code that subclasses
59|#     BaseExtractor with can_handle() and extract() methods.
60|#   - Minimum recommended: qwen2.5-coder:3b (~2GB, CPU-friendly)
61|#   - Better results: qwen2.5-coder:7b or deepseek-coder-v2-light:16b-a14b
62|#   - General-purpose models (llama3, mistral, HY-MT2) will NOT produce usable
63|#     extractors — they lack code generation training and will waste tokens.
64|#   - Generation timeout is 120s to account for long code output.
65|#
66|# To enable: set both URL and MODEL below (or pass --generator-url /
67|# --generator-model on the analyzer CLI). When either is empty, the
68|# heuristic template is used with no Ollama calls.
69|
70|EXTRACTOR_GENERATOR_URL=""        # e.g. "http://localhost:11434" (empty = disabled)
71|EXTRACTOR_GENERATOR_MODEL=""      # e.g. "qwen2.5-coder:3b" (empty = disabled)
72|
73|# Seconds between each probe request during full sweeps
74|PROBE_DELAY=8
75|
76|# Seconds between probes for reachable-only health check (faster)
77|PROBE_REACHABLE_DELAY=3
78|
79|# Hours threshold for "stale" catch-up (re-probe sites older than this)
80|STALE_HOURS=24
81|
82|# Max sites to analyze per deep_analysis run (0 = all pending)
83|ANALYSIS_LIMIT=0
84|
85|# Max summaries to translate per run (0 = all pending)
86|TRANSLATE_LIMIT=0
87|
88|# Max targets for reachable-only health check (use 0 or unset for all)
89|PROBE_REACHABLE_COUNT=20
90|
91|# Directory for log files
92|LOGDIR="./logs"
93|
94|###############################################################################
95|# INTERNAL — parse arguments, initialize venv and directories
96|###############################################################################
97|
98|FORCE=false
99|VERBOSE=false
100|ACTION="${1:-help}"
101|LIMIT_NEXT=false
102|for arg in "$@"; do
103|    [ "$arg" = "-v" ] && VERBOSE=true
104|    [ "$arg" = "--force" ] && FORCE=true
105|    # Support --limit N as runtime override for analyze/translate batches
106|    if [ "$arg" = "--limit" ]; then
107|        LIMIT_NEXT=true
108|        continue
109|    fi
110|    if [ "$LIMIT_NEXT" = "true" ]; then
111|        ANALYSIS_LIMIT="$arg"
112|        TRANSLATE_LIMIT="$arg"
113|        LIMIT_NEXT=false
114|    fi
115|done
116|
117|echo "pipeline.sh v${VERSION}" >&2
118|
119|if [ -f "$PROJECT/.venv/bin/python3" ]; then
120|    PYTHON="$PROJECT/.venv/bin/python3"
121|elif command -v python3 >/dev/null 2>&1; then
122|    PYTHON="python3"
123|else
124|    PYTHON="/usr/bin/python3"
125|fi
126|
127|# Force unbuffered output so verbose streaming works in real time
128|export PYTHONUNBUFFERED=1
129|
130|mkdir -p "$LOGDIR"
131|
132|log() {
133|    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGDIR/pipeline.log" >&2
134|}
135|
136|# Run a command, writing output to LOGDIR/<logfile>.
137|# If VERBOSE is set, also stream output live to the terminal.
138|run_cmd() {
139|    local logfile="$1"; shift
140|    if $VERBOSE; then
141|        echo "[${FUNCNAME[1]}] Streaming to $logfile ..." >&2
142|        "$@" 2>&1 | stdbuf -oL tee -a "$LOGDIR/$logfile"
143|        local rc=${PIPESTATUS[0]}
144|        echo "[${FUNCNAME[1]}] DONE (rc=$rc) — see $LOGDIR/$logfile" >&2
145|        return $rc
146|    else
147|        "$@" >> "$LOGDIR/$logfile" 2>&1
148|    fi
149|}
150|
151|###############################################################################
152|# LAYER 1 — PROBE SWEEP (network reachability)
153|###############################################################################
154|
155|_probe_count() {
156|    # Pre-flight: query DB for target count before the layer starts
157|    local FILTER="$1"
158|    $PYTHON -c "
159|import sqlite3, sys
160|try:
161|    c = sqlite3.connect('$DB')
162|    cnt = 0
163|    if '$FILTER' == 'all':
164|        cnt = c.execute('SELECT COUNT(*) FROM address_book').fetchone()[0]
165|    elif '$FILTER' == 'reachable_only':
166|        cnt = c.execute('SELECT COUNT(*) FROM address_book WHERE reachable=1').fetchone()[0]
167|    elif '$FILTER' == 'never_probed':
168|        cnt = c.execute('SELECT COUNT(*) FROM targets WHERE last_probed_at IS NULL OR last_probed_at=0').fetchone()[0]
169|    elif '$FILTER' == 'stale':
170|        import time
171|        cutoff = time.time() - $STALE_HOURS*3600
172|        cnt = c.execute('SELECT COUNT(*) FROM targets WHERE last_probed_at < ? OR last_probed_at=0', (cutoff,)).fetchone()[0]
173|    print(cnt)
174|except Exception as e:
175|    print('?', file=sys.stderr)
176|    print(0)
177|" 2>/dev/null || echo "0"
178|}
179|
180|probe_all() {
181|    local COUNT="${1:-}"
182|    local TOTAL
183|    TOTAL=$(_probe_count all)
184|    log "LAYER 1: Full sweep of all targets ($TOTAL targets)"
185|    if [ -n "$COUNT" ] && [ "$COUNT" -gt 0 ]; then
186|        run_cmd probe_all.log $PYTHON probe_sweep.py --sweep-filter all \
187|            --db "$DB" --delay "$PROBE_DELAY" --count "$COUNT" \
188|            --ollama-url "$TRANSLATION_URL" --translation-model "$TRANSLATION_MODEL"
189|    else
190|        run_cmd probe_all.log $PYTHON probe_sweep.py --sweep-filter all \
191|            --db "$DB" --delay "$PROBE_DELAY" \
192|            --ollama-url "$TRANSLATION_URL" --translation-model "$TRANSLATION_MODEL"
193|    fi
194|}
195|
196|probe_reachable() {
197|    local COUNT="${1:-$PROBE_REACHABLE_COUNT}"
198|    local TOTAL
199|    TOTAL=$(_probe_count reachable_only)
200|    log "LAYER 1: Reachable-only health check ($TOTAL targets, limit=${COUNT})"
201|    if [ "$COUNT" -gt 0 ] 2>/dev/null; then
202|        run_cmd probe_reachable.log $PYTHON probe_sweep.py --sweep-filter reachable_only \
203|            --db "$DB" --delay "$PROBE_REACHABLE_DELAY" --count "$COUNT" \
204|            --ollama-url "$TRANSLATION_URL" --translation-model "$TRANSLATION_MODEL"
205|    else
206|        run_cmd probe_reachable.log $PYTHON probe_sweep.py --sweep-filter reachable_only \
207|            --db "$DB" --delay "$PROBE_REACHABLE_DELAY" \
208|            --ollama-url "$TRANSLATION_URL" --translation-model "$TRANSLATION_MODEL"
209|    fi
210|}
211|
212|probe_new_imports() {
213|    local TOTAL
214|    TOTAL=$(_probe_count never_probed)
215|    log "LAYER 1: Sync addressbook + probe never_probed ($TOTAL new targets)"
216|    run_cmd probe_new.log $PYTHON probe_sweep.py --load-address-book \
217|        --sweep-filter never_probed --db "$DB" \
218|        --ollama-url "$TRANSLATION_URL" --translation-model "$TRANSLATION_MODEL"
219|}
220|
221|probe_stale() {
222|    local HOURS="${1:-$STALE_HOURS}"
223|    local TOTAL
224|    TOTAL=$(_probe_count stale)
225|    log "LAYER 1: Stale catch-up (>$HOURS hours, $TOTAL targets)"
226|    run_cmd probe_stale.log $PYTHON probe_sweep.py --sweep-filter stale \
227|        --min-age-hours "$HOURS" --db "$DB" \
228|        --ollama-url "$TRANSLATION_URL" --translation-model "$TRANSLATION_MODEL"
229|}
230|
231|###############################################################################
232|# LAYER 2 — TRANSLATE SUMMARIES (non-English → English via Ollama)
233|###############################################################################
234|
235|_translate_count() {
236|    # Pre-flight: count entries needing translation
237|    $PYTHON -c "
238|import sqlite3, sys
239|try:
240|    c = sqlite3.connect('$DB')
241|    cnt = c.execute(\"SELECT COUNT(*) FROM address_book WHERE detected_lang NOT IN ('en', NULL, '') AND content_summary NOT LIKE '[original:%%']\").fetchone()[0]
242|    print(cnt)
243|except Exception:
244|    print(0)
245|" 2>/dev/null || echo "0"
246|}
247|
248|translate_summaries() {
249|    local TOTAL
250|    TOTAL=$(_translate_count)
251|    local LIMIT_ARG=""
252|    if [ "$TRANSLATE_LIMIT" -gt 0 ]; then
253|        LIMIT_STR="limit=${TRANSLATE_LIMIT}"
254|        LIMIT_ARG="--limit $TRANSLATE_LIMIT"
255|    else
256|        LIMIT_STR="all pending"
257|    fi
258|    log "LAYER 2: Translate non-English summaries ($TOTAL to translate, ${LIMIT_STR})"
259|    run_cmd translate.log $PYTHON translate_summaries.py --ollama-url "$SUMMARY_URL" \
260|        --ollama-model "$SUMMARY_MODEL" \
261|        $LIMIT_ARG
262|}
263|
264|###############################################################################
265|# LAYER 3 — DEEP ANALYSIS (Ollama JSON for content understanding)
266|###############################################################################
267|
268|_analyze_count() {
269|    # Pre-flight: count entries needing deep analysis
270|    $PYTHON -c "
271|import sqlite3, sys
272|try:
273|    c = sqlite3.connect('$DB')
274|    cnt = c.execute(\"SELECT COUNT(*) FROM address_book WHERE reachable=1 AND interest_score IS NULL\").fetchone()[0]
275|    print(cnt)
276|except Exception:
277|    print(0)
278|" 2>/dev/null || echo "0"
279|}
280|
281|analyze_reachable() {
282|    local TOTAL
283|    TOTAL=$(_analyze_count)
284|    local LIMIT_ARG=""
285|    if [ "$ANALYSIS_LIMIT" -gt 0 ]; then
286|        LIMIT_STR="limit=${ANALYSIS_LIMIT}"
287|        LIMIT_ARG="--limit $ANALYSIS_LIMIT"
288|    else
289|        LIMIT_STR="all pending"
290|    fi
291|    log "LAYER 3: Deep analysis of reachable sites ($TOTAL to analyze, ${LIMIT_STR})"
292|    run_cmd analyze_reachable.log $PYTHON src/deep_analysis.py --mode reachable \
293|        --ollama-url "$ANALYSIS_URL" --ollama-model "$ANALYSIS_MODEL" \
294|        $LIMIT_ARG
295|}
296|
297|analyze_stale() {
298|    local TOTAL
299|    TOTAL=$(_analyze_count)
300|    local LIMIT_ARG=""
301|    if [ "$ANALYSIS_LIMIT" -gt 0 ]; then
302|        LIMIT_STR="limit=${ANALYSIS_LIMIT}"
303|        LIMIT_ARG="--limit $ANALYSIS_LIMIT"
304|    else
305|        LIMIT_STR="all pending"
306|    fi
307|    log "LAYER 3: Re-analyze old entries ($TOTAL to analyze, ${LIMIT_STR})"
308|    run_cmd analyze_stale.log $PYTHON src/deep_analysis.py --mode stale \
309|        --ollama-url "$ANALYSIS_URL" --ollama-model "$ANALYSIS_MODEL" \
310|        $LIMIT_ARG
311|}
312|
313|###############################################################################
314|# LAYER 4 — EXTRACTOR GENERATION (for flagged/needs_review sites)
315|###############################################################################
316|
317|_extractor_count() {
318|    # Pre-flight: count flagged sites
319|    $PYTHON -c "
320|import sqlite3, sys
321|try:
322|    c = sqlite3.connect('$DB')
323|    cnt = c.execute(\"SELECT COUNT(*) FROM address_book WHERE site_classification='needs_review' OR needs_review=1\").fetchone()[0]
324|    print(cnt)
325|except Exception:
326|    print(0)
327|" 2>/dev/null || echo "0"
328|}
329|
330|generate_extractors() {
331|    local CONFIRM="${1:-dry-run}"
332|    local TOTAL
333|    TOTAL=$(_extractor_count)
334|    local GEN_ARGS=""
335|    if [ -n "$EXTRACTOR_GENERATOR_URL" ] && [ -n "$EXTRACTOR_GENERATOR_MODEL" ]; then
336|        GEN_ARGS="--generator-url $EXTRACTOR_GENERATOR_URL --generator-model $EXTRACTOR_GENERATOR_MODEL"
337|    fi
338|    if [ "$FORCE" = "true" ]; then
339|        GEN_ARGS="$GEN_ARGS --force"
340|    fi
341|    if [ "$CONFIRM" = "dry" ]; then
342|        log "LAYER 4: Dry-run extractor generation ($TOTAL flagged sites)"
343|        run_cmd extractor_gen.log $PYTHON src/analyzer.py all-flagged $GEN_ARGS
344|    else
345|        log "LAYER 4: Write extractors to disk ($TOTAL flagged sites)"
346|        run_cmd extractor_gen_confirm.log $PYTHON src/analyzer.py all-flagged --confirm $GEN_ARGS
347|    fi
348|}
349|
350|###############################################################################
351|# LAYER 5 — EXPORT (generate browse UI / address book files)
352|###############################################################################
353|
354|_export_count() {
355|    # Pre-flight: count entries in address book
356|    $PYTHON -c "
357|import sqlite3, sys
358|try:
359|    c = sqlite3.connect('$DB')
360|    cnt = c.execute('SELECT COUNT(*) FROM address_book').fetchone()[0]
361|    print(cnt)
362|except Exception:
363|    print(0)
364|" 2>/dev/null || echo "0"
365|}
366|
367|export_ui() {
368|    local OUTDIR="${1:-$OUTPUT_DIR}"
369|    local TOTAL
370|    TOTAL=$(_export_count)
371|    log "LAYER 5: Export address book to $OUTDIR/ ($TOTAL entries)"
372|    # Truncate log so grep only sees this run's output
373|    : > "$LOGDIR/export.log"
374|    run_cmd export.log $PYTHON probe_sweep.py export --output-dir "$OUTDIR" --db "$DB"
375|
376|    # Replay the file listing from the export output (cp -v style)
377|    grep -E '^  (HTML|TXT|IDX):' "$LOGDIR/export.log" 2>/dev/null | while read -r line; do
378|        log "  $line"
379|    done
380|}
381|
382|###############################################################################
383|# COMBINED PIPELINE RUNS
384|###############################################################################
385|
386|run_full_pipeline() {
387|    log "========================================"
388|    log "FULL PIPELINE START"
389|    log "========================================"
390|    # Show the plan upfront with target counts
391|    local PROBE_NEW CNT_ALL CNTRP CNTR CNTE CNTX
392|    PROBE_NEW=$(_probe_count never_probed)
393|    CNT_ALL=$(_probe_count all)
394|    CNTRP=$(($PROBE_REACHABLE_COUNT))
395|    CNTR=$(_translate_count)
396|    CNTE=$(_analyze_count)
397|    CNTX=$(_extractor_count)
398|    local LIMIT_LABEL_T=""
399|    if [ "$TRANSLATE_LIMIT" -gt 0 ]; then
400|        LIMIT_LABEL_T="limit=${TRANSLATE_LIMIT}"
401|    else
402|        LIMIT_LABEL_T="all"
403|    fi
404|    local LIMIT_LABEL_E=""
405|    if [ "$ANALYSIS_LIMIT" -gt 0 ]; then
406|        LIMIT_LABEL_E="limit=${ANALYSIS_LIMIT}"
407|    else
408|        LIMIT_LABEL_E="all"
409|    fi
410|    log "PLAN: L1-sync($PROBE_NEW new) → L1-probe($CNT_ALL) → L2-translate($CNTR ${LIMIT_LABEL_T}) → L3-analyze($CNTE ${LIMIT_LABEL_E}) → L4-extract-dry($CNTX) → L5-export"
411|    probe_new_imports
412|    probe_all
413|    translate_summaries
414|    analyze_reachable
415|    generate_extractors dry
416|    export_ui
417|    log "========================================"
418|    log "FULL PIPELINE COMPLETE"
419|    log "========================================"
420|}
421|
422|run_daily_refresh() {
423|    log "DAILY REFRESH: reachable sweep + translate + analysis + export"
424|    probe_reachable
425|    translate_summaries
426|    analyze_reachable
427|    export_ui
428|}
429|
430|run_stale_catchup() {
431|    log "STALE CATCHUP: re-probe old sites + translate + re-analyze"
432|    probe_stale "$STALE_HOURS"
433|    translate_summaries
434|    analyze_stale
435|}
436|
437|###############################################################################
438|# CLI interface — pass action name as first arg
439|###############################################################################
440|
441|case "$ACTION" in
442|    full)       run_full_pipeline ;;
443|    daily)      run_daily_refresh ;;
444|    stale)      run_stale_catchup ;;
445|    probe-all)  probe_all ;;
446|    probe-reach) probe_reachable ;;
447|    probe-new)  probe_new_imports ;;
448|    probe-stale) probe_stale "${2:-$STALE_HOURS}" ;;
449|    analyze)    analyze_reachable ;;
450|    re-analyze) analyze_stale ;;
451|    translate)  translate_summaries ;;
452|    extractors-dry) generate_extractors dry ;;
453|    extractors) generate_extractors write ;;
454|    export)
455|        # Strip -v from positional args so it doesn't become $2 (output dir)
456|        EXDIR="${2:-}"
457|        [ "$EXDIR" = "-v" ] && EXDIR=""
458|        export_ui "${EXDIR:-$OUTPUT_DIR}" ;;
459|    help|*)
460|        echo "I2P Indexer Pipeline v${VERSION} — Layered Cron Orchestrator"
461|        cat <<EOF
462|
463|Usage: $0 <action> [options] [-v]
464|
465|Actions (layered pipeline):
466|  full          Sync addressbook, probe all, translate, analyze, extract, export
467|  daily         Reachable check + translate + analysis + export (daily cron target)
468|  stale         Re-probe old sites + translate + re-analyze with new prompt fields
469|
470|Layer commands:
471|  probe-all     L1 — Full sweep of all targets
472|  probe-reach   L1 — Reachable-only health check
473|  probe-new     L1 — Load addressbook, probe never_probed entries
474|  probe-stale [H] L1 — Stale catch-up (default $STALE_HOURS h)
475|
476|  analyze       L3 — Deep analysis of reachable/never-analyzed sites
477|  re-analyze    L3 — Re-analyze old entries with updated prompt fields
478|  translate     L2 — Translate non-English summaries via Ollama
479|
480|  extractors-dry L4 — Preview extractor generation for flagged sites
481|  extractors      L4 — Write extractors and clear flags
482|
483|  export [DIR]    L5 — Export address book HTML/TXT to DIR (default: \$OUTPUT_DIR)
484|
485|Options:
486|  -v            Verbose output (stream logs to terminal)
487|  --force       Overwrite existing extractors even if they already exist
488|  --limit N     Max sites for translate/analyze layers (default: all pending)
489|
490|Per-feature AI model config (override via env vars or source .env):
491|  TRANSLATION_MODEL  Probe-sweep translation model (default: RogerBen/HY-MT2-1.8B:latest)
492|  ANALYSIS_MODEL     Deep analysis model (default: RogerBen/HY-MT2-1.8B:latest)
493|  SUMMARY_MODEL      Summary translation model (default: llama3.2)
494|  TRANSLATION_URL    Translation endpoint (default: http://localhost:11434)
  ANALYSIS_URL         Deep analysis endpoint (default: http://localhost:11434)
  SUMMARY_URL          Summary translation endpoint (default: http://localhost:11434)
495|
496|Schedule with system cron or hermes kanban:
497|
498|  System cron examples (adjust path):
499|    0 4 * * * /path/to/I2P-Indexer/pipeline.sh daily
500|    0 2 * * 0 /path/to/I2P-Indexer/pipeline.sh full
501|    0 */6 * * * /path/to/I2P-Indexer/pipeline.sh stale
502|
503|  Or queue via kanban (runs on your agent profile):
504|    hermes kanban create --assignee '<agent-profile>' \
505|      --body 'bash pipeline.sh daily' "Daily I2P refresh"
506|EOF
507|        ;;
508|esac
509|