#!/usr/bin/env python3
import sys, os
os.chdir("/home/stefan/Projects/I2P Indexer")
sys.path.insert(0, ".")
from src.integration import discover_addresses, get_address_book, print_address_book
from src.config import I2PConfig

T = [
    ("", 
