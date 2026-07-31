# Testing Strategy

## Conventions

The I2P Indexer follows a **test-per-module** discipline. Every source file in `src/` has a corresponding test file in `tests/`:

| Module | Tests | Focus |
|---|---|---|
| `src/models.py` | `test_models.py` | Dataclasses, frozen fields, bandwidth classification |
| `src/addressbook.py` | `test_addressbook.py` | AddressBookCatalog scan/persist/query/close |
| `src/i2p_proxy.py` | `test_i2p_proxy.py` | ProxyClient, SAM client, fetch_i2p, response parsing |
| `src/proxy_client.py` | `test_proxy.py` | SOCKS5 + HTTP proxy client wrapping |
| `src/integration.py` | `test_integration.py` | DiscoveryDB CRUD, probe loop, content classification |
| `src/rtr_parser.py` | `test_rtr_parser.py` | `.rtr` binary file parsing |
| `src/ls64_parser.py` | `test_ls64_parser.py` | `.ls64` binary file parsing |

Total: **113 collected tests** (~92 pass, ~1 skipped for live proxy health, ~1 xfail for edge case).

## Isolation Guarantees

No test touches the real I2P daemon or filesystem by default. Isolation strategies:

### Database isolation
- `DiscoveryDB` accepts a `db_path` parameter. Tests use **`:memory:`** databases via pytest fixtures.
- No global singleton — even helpers like `query_db()` accept explicit paths.
- Each test class gets its own temporary DB instance (teardown via fixture scope).

### Network isolation
- `fetch_i2p()` is mocked at the module level (`@patch("src.integration.fetch_i2p")`).
- Mock responses are `Response` dataclasses with realistic shapes (status 200, body bytes, title text).
- The SOCKS5 health check test (`test_probe_health`) is **skipped** unless the daemon is confirmed reachable.

### File system isolation
- Addressbook catalog tests use temporary directories (`tmp_path` fixture) populated with hand-crafted `.rtr`/`.ls64` files.
- No real `netdb/` scanning in test suite.

## Fixture Architecture

```python
# Example pattern from test_integration.py:
@pytest.fixture
def mock_resp():
    """Build Response-like mocks for fetch_i2p patches."""
    def _build(status=200, body_len=1234, title_text="OK Page"):
        mock = MagicMock()
        # ... configure response shape ...
        return mock
    return _build

@pytest.fixture
def test_db(tmp_path):
    """Return a fresh DiscoveryDB on a temporary path."""
    dbp = str(tmp_path / "test_indexer.db")
    db = DiscoveryDB(db_path=dbp)
    yield db
    db.close()
```

The `mock_resp` factory produces consistent response shapes. The `test_db` fixture guarantees database cleanup after each test.

## Running Tests

```bash
# Full suite (verbose):
pytest -v

# Specific module:
pytest tests/test_integration.py -v

# With coverage report:
pytest --cov=src --cov-report=term-missing

# Skip live proxy test entirely:
pytest --ignore=tests/test_i2p_proxy.py
```

## Test Categories

### Unit tests (majority)
Test individual functions and classes with mocked external dependencies. These include:
- Dataclass construction, sorting, property access
- `_classify_content()` heuristic matching against known keywords
- `record_discovery()` upsert logic (idempotency checks, duplicate handling)
- Addressbook parsing of hand-crafted binary files

### Integration tests
Verify multi-component interactions without external I/O:
- Full probe cycle: mock response → DiscoveryResult → SQLite insert → query verification
- Multi-site discovery with hash-only, DNS-only, and tuple targets
- Content type bucket detection across forum/wiki/blog/etc. patterns

### Live connectivity test (skipped by default)
`test_probe_health` in `test_i2p_proxy.py` attempts a real HTTP proxy health check. It is **xfail/skip** because the daemon may not be running in CI or test environments. Uncomment to verify local setup:

```bash
pytest tests/test_i2p_proxy.py::test_probe_health -v --runxfail
```

## Adding New Tests

When adding a new feature:

1. **Identify the module** in `src/` and create/update the corresponding test file.
2. **Use dependency injection** — never hardcode paths or network calls.
3. **Mock external deps** at the highest possible level (`fetch_i2p`, not individual socket calls).
4. **Assert both success and error paths** — tests should cover happy data AND exception handling.
5. **Run the full suite** before committing (`pytest -v`).

## Known Edge Cases

| Case | Test status | Notes |
|---|---|---|
| Empty body response (status 204) | Covered | Content classification returns empty strings |
| Non-UTF-8 encoding in body | Covered | `errors="replace"` on decode |
| Duplicate hash probed via b32+DNS | Covered | Two rows in `discoveries`, both recorded independently |
| Database path doesn't exist | Covered | Auto-created by SQLite; test confirms no FileNotFoundError |
| Bandwidth classification boundary values | xfail | Edge case at exactly 48/256/2048 kbps intentionally marked expected failure |
