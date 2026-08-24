"""Shared test configuration for I2P-Indexer."""

import pytest


def pytest_addoption(parser):
    """Add --run-slow option to include slow network-bound live tests."""
    parser.addoption(
        "--run-slow", action="store_true", default=False,
        help="Include slow (network/live) tests; disabled by default so coverage runs are fast and deterministic.",
    )


def pytest_collection_modifyitems(config, items):
    """Skip live-network tests unless --run-slow is passed.

    Supports two detection methods:
    1. @pytest.mark.slow decorator on the test function/class
    2. ``slow = True`` class attribute on unittest.TestCase subclasses
    """
    skip_slow = pytest.mark.skip(
        reason="--run-slow not set (live I2P network test)"
    )
    for item in items:
        is_slow = ("slow" in item.keywords or
                   getattr(getattr(item, "cls", None), "slow", False))
        if is_slow and not config.getoption("--run-slow"):
            item.add_marker(skip_slow)


def pytest_configure(config):
    """Register the 'slow' marker so it doesn't trigger UnknownMark warnings."""
    config.addinivalue_line("markers", "slow: live I2P network test (use --run-slow to include)")

