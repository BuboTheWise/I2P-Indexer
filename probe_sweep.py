#!/usr/bin/env python3
"""I2P Indexer — discovery sweep with SUSI DNS export support.

Performs HTTP probing of .i2p destinations through the local I2P proxy,
records results in a persistent SQLite database, and supports filtering
which targets to probe via --sweep-filter.

The target queue prioritises previously reachable sites first, then valid b32
hashes, and finally by last_probed_at (oldest probes re-probed first).

--- Sweep filter modes ---

  --sweep-filter all            Probe every target in the database.
                                Use for full baseline sweeps (e.g. weekly cron).
                                This is the default when no filter is given.

  --sweep-filter reachable_only Only reprobe targets that have been reachable
                                at least once. Ideal for daily health checks on
                                known-live sites since it skips dead/unknown entries
                                and completes much faster.

  --sweep-filter never_probed   Probe only targets where last_probed_at == 0, i.e.,
                                freshly imported entries that have never been touched.
                                Use after loading a new addressbook or SUSI export so
                                you don't waste time re-probing what you already checked.

  --sweep-filter stale          Probe targets whose last probe is older than
                                --min-age-hours (default 24h). Catches sites that
                                may have changed or gone offline since the last sweep.
                                Combine with --dry-run to inspect the matching set
                                before launching a real probe.

--- Usage examples ---

    # Quick health check of I2P router:
    python3 probe_sweep.py --check-health

    # Wait for network readiness, then probe up to 50 targets slowly:
    python3 probe_sweep.py --wait-for-i2p 600 --count 50 --delay 3

    # Load addressbook + sweep all newly imported entries:
    python3 probe_sweep.py --load-address-book --sweep-filter never_probed

    # Import SUSI DNS export, then sweep everything in one shot:
    python3 probe_sweep.py --import-export data/address_book_export.txt

    # Daily reachable-sites check (fast — skips dead entries):
    python3 probe_sweep.py --sweep-filter reachable_only

    # Stale refresh — re-probe anything not checked in 48 hours:
    python3 probe_sweep.py --sweep-filter stale --min-age-hours 48

    # Dry run — list what would be probed without actually sending requests:
    python3 probe_sweep.py --dry-run --sweep-filter reachable_only

    # Auto-crawl control — discover linked sites up to depth 2:
    python3 probe_sweep.py --crawl-depth 2 --max-new-targets 100

    # Export address book as website files:
    python3 probe_sweep.py export --output-dir website

--- Cron job usage patterns ---

  # Weekly full baseline (every Sunday 02:00):
  0 2 * * 0 python3 probe_sweep.py --sweep-filter all --delay 8

  # Daily reachable refresh (04:00, skips known-dead entries):
  0 4 * * * python3 probe_sweep.py --sweep-filter reachable_only --delay 3

  # Stale site catch-up (hourly, anything not probed in 24h):
  0 * * * * python3 probe_sweep.py --sweep-filter stale --min-age-hours 24

  # After addressbook load — first pass on new imports only:
  python3 probe_sweep.py --load-address-book --sweep-filter never_probed
"""
import argparse
import json as _json
import logging
import os
import sys
from datetime import datetime, timezone

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ".")

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

from src.export_website import (
    generate_address_book_html,
    generate_address_book_txt,
    generate_index_html,
)

from src.addressbook import AddressBookCatalog
from src.i2p_health import check_i2p_health as _check_i2p_health
from src.integration import (
    DEFAULT_DB_PATH,
    DiscoveryDB,
    discover_addresses,
    parse_susi_export,
    print_address_book,
    get_address_book,
)


def load_and_reconcile_addressbook(db: DiscoveryDB):
    """Scan netdb / webconsole for addressbook entries and load into targets."""
    from src.config import I2PConfig

    cfg = I2PConfig()

    # Try scanning the project-local netdb directory first
    netdb_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "netdb")
    catalog = AddressBookCatalog(netdb_dir=netdb_dir, config=cfg)

    loaded = catalog.load()

    if loaded == 0:
        print("  No .rtr/.ls64 files in netdb/ and webconsole fallback returned nothing.")
        print("  Tip: configure I2P router to export NetDB files to the netdb/ directory,")
        print("       or use --import-export with a SUSI DNS export file instead.")
        catalog.close()
        return

    print(f"  AddressBook loaded {loaded} entries. ({catalog.summary()})")

    # Load into targets table with source='addressbook'
    count = db.load_addressbook(catalog)
    print(f"  Upserted {count} addressbook destinations into targets table.")

    # Reconcile: mark stale entries from previous addressbook loads
    reconcile_result = db.reconcile_addressbook(catalog)
    if reconcile_result["marked_stale"] > 0:
        print(
            f"  Reconciliation: {reconcile_result['updated']} updated, "
            f"{reconcile_result['marked_stale']} marked stale."
        )

    catalog.close()


def generate_report(db_path: str, output_path: str) -> None:
    """Generate a detailed per-site markdown report of the address book."""
    entries = get_address_book(db_path)
    if not entries:
        print("No address book entries to report on.")
        return

    reachable = [e for e in entries if e.get("reachable")]
    unreachable = [e for e in entries if not e.get("reachable")]

    with open(output_path, "w") as f:
        f.write("# I2P Indexer Sweep Report\n\n")
        f.write(f"**Generated:** {datetime.now(timezone.utc).isoformat()}\n\n")

        # ─── Summary table ──────────────────────────────
        f.write("## Summary\n\n")
        f.write("| Metric | Count |\n|---|---|\n")
        f.write(f"| Total unique destinations | {len(entries)} |\n")
        f.write(f"| Reachable | {len(reachable)} |\n")
        f.write(f"| Unreachable | {len(unreachable)} |\n")

        # Content type breakdown
        types_count: dict[str, int] = {}
        for e in entries:
            ct = e.get("content_type", "unknown") or "unknown"
            types_count[ct] = types_count.get(ct, 0) + 1
        f.write("\n### Content Type Breakdown\n\n")
        f.write("| Type | Count |\n|---|---|\n")
        for ct, cnt in sorted(types_count.items(), key=lambda x: -x[1]):
            f.write(f"| {ct} | {cnt} |\n")

        # ─── Detailed reachable sites ───────────────────
        f.write("\n## Reachable Sites (Detailed)\n\n")
        for i, entry in enumerate(reachable, 1):
            name = entry.get("dns_name") or entry.get("b32_addr", "UNKNOWN")
            b32 = entry.get("b32_addr") or ""
            ident = (entry.get("ident_hash_hex") or "")[:8]

            f.write(f"### {i}. {name}\n\n")
            f.write(f"- **B32:** `{b32}`\n")
            f.write(f"- **DNS:** {entry.get('dns_name', 'N/A')}\n")
            if ident:
                f.write(f"- **Hash:** `{ident}…`\n")
            sc = entry.get("status_code")
            rt = entry.get("response_time")
            f.write(f"- **Status:** {sc}")
            if rt:
                f.write(f" ({rt}s)\n")
            else:
                f.write("\n")
            ct = entry.get("content_type", "unknown") or "unknown"
            f.write(f"- **Content Type:** {ct}\n")
            title = entry.get("title") or ""
            if title:
                f.write(f"- **Title:** {title}\n")
            summary = entry.get("content_summary") or ""
            if summary:
                f.write(f"- **Summary:** {summary}\n")
            blen = entry.get("body_length", 0) or 0
            f.write(f"- **Body Size:** {blen:,} bytes\n")

            # Router metadata
            bw = entry.get("bandwidth")
            caps = entry.get("router_caps")
            leases = entry.get("num_leases")
            via = entry.get("via_method") or entry.get("probe_mode")
            probed = entry.get("last_probed_at")

            if bw:
                f.write(f"- **Bandwidth:** {int(bw)} kbps\n")
            if caps:
                f.write(f"- **Caps:** {caps}\n")
            if leases:
                f.write(f"- **Leases:** {leases}\n")
            if via:
                f.write(f"- **Probed via:** {via}\n")

            # Parse probed_at timestamp
            if probed and probed != 0 and probed != "":
                try:
                    ts = float(probed)
                    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                    f.write(f"- **Last Probed:** {dt.isoformat()}\n")
                except (ValueError, OSError):
                    f.write(f"- **Last Probed:** {probed}\n")

            # Content hash for change detection
            chash = entry.get("content_hash") or ""
            if chash:
                f.write(f"- **Content Hash:** `{chash[:16]}…`\n")
            # Last modified signal
            lm = entry.get("last_modified", "") or ""
            if lm:
                f.write(f"- **Last-Modified:** {lm}\n")
            # Found internal links
            found_l = entry.get("found_links") or "[]"
            try:
                links_list = _json.loads(found_l) if isinstance(found_l, str) else found_l
            except (ValueError, TypeError):
                links_list = []
            if links_list:
                f.write(f"- **Internal Links Found:** {len(links_list)}\n")

            # Flags array
            flags = entry.get("flags") or "[]"
            try:
                flags_list = _json.loads(flags) if isinstance(flags, str) else flags
            except (ValueError, TypeError):
                flags_list = []
            if flags_list:
                f.write(f"- **Flags ({len(flags_list)}):**\n")
                for flag in flags_list:
                    if isinstance(flag, dict):
                        f.write(f"  - {flag.get('type', '')}: {flag.get('value', '')}\n")
                    else:
                        f.write(f"  - {flag}\n")

            # Error info if present even on reachable
            err = entry.get("error_msg", "") or ""
            if err:
                f.write(f"\n<details>\n<summary>Error history</summary>\n\n```\n{err[:512]}\n```\n</details>\n")

            f.write("\n---\n\n")

        # ─── Unreachable summary ────────────────────────
        if unreachable:
            f.write(f"## Unreachable Sites ({len(unreachable)} total)\n\n")
            for entry in unreachable:
                name = entry.get("dns_name") or \
                      entry.get("b32_addr", "UNKNOWN")
                hshort = (entry.get("ident_hash_hex") or "")[:8]
                f.write(f"- `{name}` (hash: {hshort}…)\n" if hshort else
                        f"- `{name}`\n")

    print(f"Detailed report written to {output_path}")


def main():
    p = argparse.ArgumentParser(
        description="I2P Indexer — target discovery sweep",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Subcommands:\n"
            "  export    Generate website files (HTML + TXT) from the address book\n\n"
            "Examples:\n"
            "  python3 probe_sweep.py --sweep-filter reachable_only\n"
            "  python3 probe_sweep.py export --output-dir website\n"
        ),
    )

    # ── Subcommands ────────────────────────────────────────────────
    subparsers = p.add_subparsers(dest="subcommand")

    # -- export: generate address book website files --
    export_parser = subparsers.add_parser(
        "export",
        help="Generate HTML and TXT address book files for I2P eepsite hosting",
    )
    export_parser.add_argument(
        "--output-dir",
        default="website",
        help="Directory to write the exported files (default: website)",
    )
    export_parser.add_argument(
        "--db-path",
        default=None,
        help=f"Path to SQLite database (default: {DEFAULT_DB_PATH})",
    )

    # ── Global arguments (flat — apply to sweep when no subcommand) --
    p.add_argument(
        "--db",
        default=DEFAULT_DB_PATH,
        help=f"Path to SQLite database (default: {DEFAULT_DB_PATH})",
    )
    p.add_argument(
        "--delay",
        type=float,
        default=5.0,
        help="Seconds between probes (default: 5.0 — I2P is slow)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="List targets without actually probing",
    )
    p.add_argument(
        "--show-book",
        action="store_true",
        help="Print full address book after sweep",
    )
    p.add_argument(
        "--import-export",
        metavar="PATH",
        default=None,
        help="Path to SUSI DNS export file to import before sweeping",
    )
    p.add_argument(
        "--count",
        type=int,
        default=None,
        help="Limit the sweep to this many targets (default: all)",
    )
    p.add_argument(
        "--sweep-filter",
        default=None,
        choices=["reachable_only", "never_probed", "stale", "all"],
        help="Only probe targets matching this filter (default: all)",
    )
    p.add_argument(
        "--min-age-hours",
        type=float,
        default=24.0,
        help='Hours threshold for "stale" sweep filter (default: 24)',
    )
    p.add_argument(
        "--load-address-book",
        action="store_true",
        help="Scan I2P addressbook (netdb/ or webconsole) and load into targets before sweeping",
    )
    p.add_argument(
        "--probe-timeout",
        type=float,
        default=None,
        help="Per-target probe timeout in seconds (default: 120)",
    )
    p.add_argument(
        "--report",
        metavar="PATH",
        default=None,
        help="Generate a per-site markdown report after sweep completes",
    )
    p.add_argument(
        "--check-health",
        action="store_true",
        help="Show I2P router health and exit",
    )
    p.add_argument(
        "--wait-for-i2p",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Wait up to SECONDS for I2P network readiness before sweeping (default: skip wait)",
    )
    p.add_argument(
        "--crawl-depth",
        type=int,
        default=1,
        dest="crawl_depth",
        metavar="N",
        help=(
            "Maximum auto-crawl depth (default: 1 — only directly linked sites are probed). "
            "Set to 0 to disable auto-crawling entirely. Values > 1 enable recursive crawling: "
            "depth=2 probes links found in depth-1 results, etc."
        ),
    )
    p.add_argument(
        "--max-new-targets",
        type=int,
        default=50,
        dest="max_new_targets",
        metavar="N",
        help=(
            "Maximum new targets to discover via auto-crawl in a single run (default: 50). "
            "Prevents a single directory site from flooding the target queue with hundreds of links."
        ),
    )
    p.add_argument(
        "--respect-robots",
        action="store_true",
        default=False,
        help="Fetch robots.txt from each destination and skip Disallow paths during link extraction (default: off — probe everything)",
    )
    p.add_argument(
        "--no-backoff",
        action="store_true",
        default=False,
        help="Disable adaptive backoff — probe targets even when they are in their backoff window (default: respect backoff)",
    )
    p.add_argument(
        "--backoff-strategy",
        choices=["exponential", "fixed"],
        default="exponential",
        dest="backoff_strategy",
        help=(
            "Backoff algorithm for unreachable targets (default: exponential). "
            "'exponential' uses growing delays (60s → 300s → 1800s …), "
            "'fixed' applies a constant delay per failure."
        ),
    )
    p.add_argument(
        "--i2p-host",
        default="127.0.0.1",
        dest="i2p_host",
        metavar="HOST",
        help=("I2P router hostname or IP (default: 127.0.0.1)"),
    )
    p.add_argument(
        "--i2p-http-port",
        type=int,
        default=4444,
        dest="i2p_http_port",
        metavar="PORT",
        help=("I2P HTTP proxy port (default: 4444)"),
    )
    p.add_argument(
        "--i2p-socks-port",
        type=int,
        default=7656,
        dest="i2p_socks_port",
        metavar="PORT",
        help=("I2P SOCKS5 proxy port (default: 7656)"),
    )
    p.add_argument(
        "--ollama-url",
        default=None,
        dest="ollama_url",
        metavar="URL",
        help=(
            "Ollama API endpoint for local translation of non-English content. "
            "Example: http://localhost:11434. When set, detected non-English "
            "summaries are translated to English via the HY-MT2 model. "
            "(default: off — language detection and tagging only)"
        ),
    )
    p.add_argument(
        "--translation-model",
        default=None,
        dest="translation_model",
        metavar="NAME",
        help=(
            "Ollama model name for translation (default: RogerBen/HY-MT2-1.8B:latest). "
            "Allows per-feature model selection — e.g., use a smaller model for "
            "translation while deep analysis uses a larger one."
        ),
    )
    args = p.parse_args()

    # ── Validate crawl args ───────────────────────────────────────
    if args.crawl_depth < 0:
        p.error("--crawl-depth must be >= 0")
    if args.max_new_targets < 1:
        p.error("--max-new-targets must be >= 1")

    # ── Export subcommand ─────────────────────────────────────────
    if args.subcommand == "export":
        db_path = args.db_path or DEFAULT_DB_PATH
        output_dir = args.output_dir
        print(f"Exporting address book from {db_path} -> {output_dir}/")
        try:
            html_path = generate_address_book_html(db_path, output_dir)
            txt_path = generate_address_book_txt(db_path, output_dir)
            html_size = html_path.stat().st_size
            txt_size = txt_path.stat().st_size
            print(f"  HTML: {html_path} ({html_size:,} bytes)")
            print(f"  TXT:  {txt_path} ({txt_size:,} bytes)")
            idx_path = generate_index_html(output_dir)
            idx_size = idx_path.stat().st_size
            print(f"  IDX:  {idx_path} ({idx_size:,} bytes)")
            print("Export complete.")
        except Exception as e:
            print(f"Export failed: {e}")
            sys.exit(1)
        return

    # ── Health-only mode ────────────────────────────────────────
    if args.check_health:
        try:
            health = _check_i2p_health()
            print(health.summary())
        except ConnectionError as e:
            print(f"I2P console unreachable: {e}")
        return

    # ── Wait for network readiness ──────────────────────────────
    if args.wait_for_i2p is not None:
        from src.i2p_health import wait_for_i2p_ready
        print(f"Waiting up to {args.wait_for_i2p:.0f}s for I2P network readiness ...")
        try:
            health = wait_for_i2p_ready(timeout=args.wait_for_i2p)
            print("I2P ready:")
            print(health.summary())
        except TimeoutError:
            print(f"I2P not ready after {args.wait_for_i2p:.0f}s — proceeding anyway")
            logger.warning("Sweep starting with non-ready I2P network")

    # Apply --probe-timeout to module-level PROBE_TIMEOUT if set
    import src.integration as integration_module
    if args.probe_timeout is not None:
        integration_module.PROBE_TIMEOUT = args.probe_timeout

    # ── Load addressbook scan ────────────────────────────────────
    if args.load_address_book:
        print("Loading I2P addressbook ...")
        db = DiscoveryDB(args.db)
        try:
            load_and_reconcile_addressbook(db)
        finally:
            db.close()

    # ── Import from SUSI DNS export ────────────────────────────────
    if args.import_export:
        print(f"Importing SUSI export from {args.import_export} ...")
        entries = parse_susi_export(args.import_export)
        db = DiscoveryDB(args.db)
        touched = db.upsert_susi_entries(entries, source_book="router")
        total_targets = len(db.get_targets())
        print(f"  Parsed {len(entries)} entries, touched {touched} rows in DB.")
        print(f"  Total targets in DB: {total_targets}")
        db.close()

    # ── Dry run — show what would be probed ────────────────────────
    if args.dry_run:
        db = DiscoveryDB(args.db)
        targets = db.get_targets(filter_mode=args.sweep_filter or "all", min_age_hours=args.min_age_hours, skip_backoff=not args.no_backoff)
        if args.count:
            targets = targets[:args.count]
        print(f"Database: {args.db}")
        print(f"Targets in queue: {len(targets)}")
        for hash_hex, dns in targets[:20]:
            tag = dns or (hash_hex[:16] + "..." if hash_hex else "(empty)")
            print(f"  └─ {tag}")
        if len(targets) > 20:
            print(f"  ... and {len(targets) - 20} more")
        db.close()
        return

    from src.config import I2PConfig

    # ── Real sweep ───────────────────────
    from src.config import OllamaConfig

    cfg = I2PConfig(
        http_host=args.i2p_host,
        http_port=args.i2p_http_port,
        socks_port=args.i2p_socks_port,
        ollama=OllamaConfig(ollama_url=args.ollama_url or ""),
    )

    # Wire translation config into the module-level globals so the extractor
    # pipeline can access them during discovery. Each feature now gets its own
    # model via dedicated CLI args (--translation-model for extraction,
    # --ollama-model for deep analysis).
    from src import translation as trans_mod
    if cfg.ollama_url:
        trans_mod.set_ollama_url(cfg.ollama_url)
        if args.translation_model:
            trans_mod.set_ollama_model(args.translation_model)

    effective_timeout = integration_module.PROBE_TIMEOUT
    if args.respect_robots:
        print("  robots.txt filtering enabled — skipping Disallow paths")

    results = discover_addresses(
        known_addrs=None,
        config=cfg,
        db_path=args.db,
        probe_delay=args.delay,
        timeout=effective_timeout,
        filter_mode=args.sweep_filter or "all",
        min_age_hours=args.min_age_hours,
        skip_backoff=not args.no_backoff,
        backoff_strategy=args.backoff_strategy,
        respect_robots=args.respect_robots,
    )

    # Slice to --count if requested
    if args.count:
        results = results[:args.count]

    reachable = sum(1 for r in results if r.reachable)
    dead = len(results) - reachable

    print(f"\n{'='*60}")
    print(f"  I2P Sweep complete: {len(results)} probed, "
          f"{reachable} reachable, {dead} unavailable")
    print("=" * 60)
    print()

    # ── Report generation ─────────────────────────────────────────
    if args.report:
        generate_report(args.db, args.report)

    # ── Address book snapshot ─────────────────────────────────────
    if args.show_book:
        entries = get_address_book(args.db)
        print_address_book(entries)


if __name__ == "__main__":
    main()
