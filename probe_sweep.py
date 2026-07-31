#!/usr/bin/env python3
"""Manual discovery sweep — run against all targets in the database.

Usage examples:
    python3 probe_sweep.py                  # Sweep everything, default 5s delay
    python3 probe_sweep.py --delay 10       # Slower pace (I2P is slow)
    python3 probe_sweep.py --dry-run        # Show targets without probing
    python3 probe_sweep.py --show-book      # Print address book after sweep
"""
import argparse
import sys
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ".")

from src.integration import (
    DEFAULT_DB_PATH,
    DiscoveryDB,
    discover_addresses,
    print_address_book,
    get_address_book,
)


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
    args = p.parse_args()

    # ── Dry run — show what would be probed ────────────────────────
    if args.dry_run:
        db = DiscoveryDB(args.db)
        targets = db.get_targets()
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
