# Contributing Guide

## Getting Started

1. Ensure Python 3.11+ is installed and a local I2P daemon is running (Docker).
2. Clone the repository and create a virtual environment:
   ```bash
   cd "I2P-Indexer"
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
3. Verify connectivity:
   ```python
   from src.i2p_proxy import probe_health
   print(probe_health())  # should show {'backend': 'http-proxy', 'status': 'ok'}
   ```

## Development Workflow

### Before coding
1. Identify the module in `src/` that handles the feature or bug.
2. Check if a corresponding test file exists in `tests/`. If not, create one.
3. Read the relevant design docs in `docs/` for context on architecture decisions.

### During development
1. Write tests **before** or **alongside** implementation code.
2. Use dependency injection — never hardcode DB paths or network calls.
3. Mock external dependencies (`fetch_i2p`, file I/O) at the highest level possible.
4. Run `pytest tests/test_<module>.py -v` after each meaningful change.

### Before committing
1. Run the **full suite**: `pytest -v` — all tests must pass.
2. Verify no secrets leaked: check that `.env`, tokens, and credentials are in `.gitignore`.
3. Stage only changed files — do not include `__pycache__/`, `.venv/`, or `indexer.db`.

## Code Style

- **Type annotations** on all public functions and dataclass fields.
- **Docstrings** for modules, classes, and public methods (follow the style of existing code).
- **Line length**: ~100 characters max.
- **Imports**: sorted (stdlib → third-party → local), grouped by blank lines.
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes/dataclasses.

## Testing Rules

See [TESTING_STRATEGY.md](TESTING_STRATEGY.md) for the full guide. Key rules:

1. **No real network calls** in tests — mock `fetch_i2p()` at module level.
2. **No real DB files** — use `:memory:` or `tmp_path` fixtures.
3. **Assert both success and error paths** — cover happy data AND exception handling.
4. One test file per source module, named `test_<module>.py`.

## File Structure Conventions

```
src/                    ← Python package (library code)
tests/                  ← Test suite (pytest)
docs/                   ← Architecture and reference docs
results/                ← Probe output files (gitignored if large)
.venv/                  ← Virtual environment (never committed)
indexer.db*             ← SQLite database (never committed)
```

## Adding New Modules

1. Create the source file in `src/<name>.py`.
2. Export public symbols in `src/__init__.py`.
3. Create `tests/test_<name>.py` with at least one test per public function.
4. Run `pytest -v` to verify the full suite still passes.

## Reporting Issues

Include:
- Python version and OS
- Whether the I2P daemon is reachable (`probe_health()` output)
- Full traceback (no truncation)
- Whether the issue occurs in tests OR only in live probes

## Commit Message Format

```
Short description (imperative, under 50 chars)

Optional longer description with context:
- What was changed and why
- Any trade-offs or design decisions
- Related issue/task numbers if applicable
```

Examples from the repo:
- `Integration module rewrite: hash-first probing, dual-mode b32+dns`
- `Addressbook parser: .rtr/.ls64 binary parsers, catalog with webconsole fallback, 61 tests`
