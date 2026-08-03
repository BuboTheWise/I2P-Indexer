#!/usr/bin/env python3
"""I2P Indexer — discovery sweep with SUSI DNS export support.

Usage examples:
    python3 probe_sweep.py --check-health                             # Show I2P router health
    python3 probe_sweep.py --wait-for-i2p 600 --count 50 --delay 3   # Wait for readiness + probe
    python3 probe_sweep.py --load-address-book                        # Load addressbook + probe
    python3 probe_sweep.py --import-export data/address_book_export.txt  # Import + sweep all
    python3 probe_sweep.py --count 100 --delay 3                     # Probe first 100 only
    python3 probe_sweep.py --dry-run                                  # List targets without probing
    python3 probe_sweep.py --report sweep_report.txt                 # Generate report after sweep

The target queue prioritises previously reachable sites first, then valid b32
hashes, and finally by last_probed_at (oldest probes re-probed first).
"""
import argparse
import json as _json
import logging
import os
import sys
from datetime import datetime, timezone

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ".")

logger = logging.getLogger(__name__)

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
    p = argparse.ArgumentParser(description="I2P Indexer — target discovery sweep")
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
    args = p.parse_args()

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
        targets = db.get_targets()
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

    # ── Real sweep ────────────────────────────────────────────────
    effective_timeout = integration_module.PROBE_TIMEOUT
    results = discover_addresses(
        known_addrs=None,
        config=None,
        db_path=args.db,
        probe_delay=args.delay,
        timeout=effective_timeout,
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
