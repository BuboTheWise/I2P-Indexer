"""Modular content extractor system.

Each destination probed by the sweeper is fed through a registry of extractors.
The first extractor whose ``can_handle()`` returns True wins and produces the
content_type bucket, summary lines, and linked I2P sites.  If no extractor
claims the response, the destination is flagged ``needs_review`` for the
analyzer to inspect.

Plugin discovery:
    On import this module scans ``src/ext_plugins/`` (gitignored) for Python
    files that subclass ``BaseExtractor`` and auto-registers them.
"""
from __future__ import annotations

import abc
import importlib.util
import logging
import pathlib
from typing import Tuple, List, Dict, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------


class BaseExtractor(abc.ABC):
    """Base class for content extractors.

    Each extractor implements ``can_handle`` to check if it can process the
    response, and ``extract`` to produce a classification result.
    """

    # Priority (lower = higher priority). Default 100. Built-in extractors
    # override this to run before discovered plugins.
    priority: int = 100

    @abc.abstractmethod
    def can_handle(
        self,
        body_text: str,
        headers: Dict[str, str],
        status_code: int,
    ) -> bool:
        """Return True if this extractor should handle this response."""
        ...

    @abc.abstractmethod
    def extract(
        self,
        title: str,
        body_text: str,
        headers: Dict[str, str],
    ) -> Tuple[str, List[str], List[str]]:
        """Return (content_type_bucket, summary_lines, linked_i2p_sites).

        If the extractor handles the response but cannot produce meaningful
        content (e.g., HTML page with no extractable text), return an empty
        summary list ``[]`` — the orchestrator will flag it as a partial
        extract for needs_review.
        """
        ...


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_registry: List[BaseExtractor] = []


def _register(cls: type[BaseExtractor]) -> type[BaseExtractor]:
    """Decorator to register an extractor class into the global registry."""
    _registry.append(cls())
    _registry.sort(key=lambda e: (e.priority, type(e).__name__))
    return cls


def get_registry() -> List[BaseExtractor]:
    """Return the sorted list of registered extractors."""
    return list(_registry)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class ExtractorResult:
    """Structured result from run_extractors."""

    __slots__ = ("content_type", "summary_lines", "links", "needs_review", "reason")

    def __init__(self, content_type: str = "", summary_lines: List[str] | None = None,
                 links: List[str] | None = None, needs_review: bool = False,
                 reason: str = "") -> None:
        self.content_type = content_type
        self.summary_lines = summary_lines or []
        self.links = links or []
        self.needs_review = needs_review
        self.reason = reason

    @property
    def content_summary(self) -> str:
        """Join summary lines into the string format expected by DiscoveryResult."""
        return "\n".join(self.summary_lines) if self.summary_lines else ""


def run_extractors(
    title: str,
    body_text: str,
    headers: Dict[str, str] | None = None,
    status_code: int = 200,
) -> ExtractorResult:
    """Run the extractor registry and return the first successful result.

    If no extractor claims the response, return an empty result with
    ``needs_review=True`` so the destination gets flagged for analyzer
    inspection.

    Args:
        title: Extracted page title (from <title> tag or similar).
        body_text: Full response body as text (decoded from bytes).
        headers: HTTP response headers as a dict. Keys are case-insensitive.
        status_code: HTTP status code.

    Returns:
        ExtractorResult with content_type, summary_lines, links, and flags.
    """
    if headers is None:
        headers = {}

    # Normalize header keys to Title-Case for consistent matching
    norm_headers: Dict[str, str] = {}
    for k, v in headers.items():
        norm_headers[k.title()] = v

    for extractor in _registry:
        try:
            if extractor.can_handle(body_text, norm_headers, status_code):
                content_type, lines, links = extractor.extract(title, body_text, norm_headers)
                # Check if this was a "partial" (handled but low quality)
                has_body_data = len(body_text.strip()) > 200
                is_low_quality = len([l for l in lines if l.strip()]) <= 1 and has_body_data

                if is_low_quality:
                    return ExtractorResult(
                        content_type=content_type,
                        summary_lines=lines,
                        links=links,
                        needs_review=True,
                        reason="partial_extract_only",
                    )
                return ExtractorResult(
                    content_type=content_type,
                    summary_lines=lines,
                    links=links,
                )
        except Exception:
            logger.exception(f"Extractor {type(extractor).__name__} raised; skipping")

    # No extractor matched — flag for analyzer
    return ExtractorResult(
        needs_review=True,
        reason="no_extractor_claimed",
    )


# ---------------------------------------------------------------------------
# Plugin discovery
# ---------------------------------------------------------------------------

_PLUGIN_DIR = pathlib.Path(__file__).parent / "ext_plugins"


def discover_plugins() -> None:
    """Auto-discover extractors from src/ext_plugins/ directory.

    Scans for Python files (excluding __init__.py and private modules),
    imports them, and registers any BaseExtractor subclasses found.
    """
    if not _PLUGIN_DIR.is_dir():
        logger.info("ext_plugins/ directory not found, skipping plugin discovery")
        return

    for pkg_file in sorted(_PLUGIN_DIR.glob("*.py")):
        if pkg_file.name.startswith("_"):
            continue
        module_name = pkg_file.stem
        try:
            spec = importlib.util.spec_from_file_location(
                f"src.ext_plugins.{module_name}", pkg_file
            )
            if spec is None or spec.loader is None:
                logger.warning(f"Cannot load plugin {pkg_file}")
                continue
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            logger.info(f"Loaded extractor plugin: {module_name}")
        except Exception:
            logger.exception(f"Failed to load plugin {pkg_file}")


# Auto-discover plugins when the module is imported
discover_plugins()
