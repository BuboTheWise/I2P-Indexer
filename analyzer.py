#!/usr/bin/env python3
"""I2P Indexer Analyzer — re-exports src.analyzer for convenience."""
import sys
sys.path.insert(0, ".")

from src.analyzer import main  # noqa: F401

if __name__ == "__main__":
    sys.argv[0] = "analyzer.py"
    main()
