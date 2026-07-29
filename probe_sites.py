#!/usr/bin/env python3
"""Quick I2P eepsite probe script."""
import httpx
import json

PROXY = 'http://127.0.0.1:4444'
SITES = [
    ('I2P-Stat', 'http://i2p-stat.i2p/'),
    ('I2P-Projekt', 'http://i2p-projekt.i2p/'),
]

results = []
for name, url in SITES:
    try:
        with httpx.Client(proxy=PROXY, timeout=httpx.Timeout(60)) as c:
            r = c.get(url)
            body = r.text[:300]
            results.append({'name': name, 'status': r.status_code, 'body_start': body})
    except Exception as e:
        results.append({'name': name, 'error': str(e)})

json.dump(results, open('/home/stefan/Projects/I2P Indexer/results/probe.json', 'w'), indent=2)
print(json.dumps(results, indent=2))
