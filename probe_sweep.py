#!/usr/bin/env python3
"""I2P Indexer — discovery sweep with SUSI DNS export support.

Usage examples:
    python3 probe_sweep.py --load-address-book                     # Load addressbook + probe
    python3 probe_sweep.py --import-export data/address_book_export.txt  # Import + sweep all
    python3 probe_sweep.py --count 100 --delay 3                    # Probe first 100 only
    python3 probe_sweep.py --dry-run                                # List targets without probing
"""
import argparse
import sys
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ".")

from src.addressbook import AddressBookCatalog
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
    args = p.parse_args()

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
    results = discover_addresses(
        known_addrs=None,
        config=None,
        db_path=args.db,
        probe_delay=args.delay,
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

    # ── Address book snapshot ─────────────────────────────────────
    if args.show_book:
        entries = get_address_book(args.db)
        print_address_book(entries)


if __name__ == "__main__":
    main()
