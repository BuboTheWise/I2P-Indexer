"""Tests for src.export_website — HTML and TXT generators."""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from src.export_website import (
    generate_address_book_html,
    generate_address_book_txt,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sample_db(tmp_path: pathlib.Path):
    """Populate a minimal I2P Indexer DB so get_address_book returns rows."""
    from src.integration import DiscoveryDB

    db = DiscoveryDB(str(tmp_path / "test.db"))
    # Two destinations via record_discovery.
    db.record_discovery(
        ident_hash_hex="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        b32_addr="aaaaa.i2p",
        i2p_dns_name="ok-test.i2p",
        probe_mode="b32",
        reachable=True,
        status_code=200,
        body_length=4096,
        title="OK Test Site",
        response_time=1.5,
        via_method="https",
        content_type="blog",
        content_summary="A test site",
    )
    db.record_discovery(
        ident_hash_hex="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        b32_addr="bbbbb.i2p",
        i2p_dns_name="down-test.i2p",
        probe_mode="b32",
        reachable=False,
        status_code=0,
        body_length=0,
        title="",
        response_time=60.2,
        via_method="https",
        content_type="",
        content_summary="",
    )
    db.close()
    return str(tmp_path / "test.db")


def _make_empty_db(tmp_path: pathlib.Path):
    """Create a fresh DB with schema but no data."""
    from src.integration import DiscoveryDB

    db = DiscoveryDB(str(tmp_path / "empty.db"))
    db.close()
    return str(tmp_path / "empty.db")


def _extract_entries(html: str) -> list[dict]:
    """Pull the embedded ENTRIES array out of generated HTML."""
    start = html.index("const ENTRIES  = ") + len("const ENTRIES  = ")
    end = html.index(";", start)
    raw = html[start:end]
    return json.loads(raw)


def _extract_timeline(html: str) -> list[dict]:
    """Pull the embedded TIMELINE array out of generated HTML."""
    start = html.index("const TIMELINE = ") + len("const TIMELINE = ")
    end = html.index(";", start)
    raw = html[start:end]
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Integration — generate_address_book_html (interactive browse UI)
# ---------------------------------------------------------------------------

class TestGenerateAddressBookHtml:
    def test_creates_file(self, tmp_path: pathlib.Path):
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        assert result.is_file()
        assert result.name == "address_book.html"

    def test_contains_data(self, tmp_path: pathlib.Path):
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        entries = _extract_entries(content)
        dns_names = [e["dns_name"] for e in entries]
        assert "ok-test.i2p" in dns_names
        assert any("bbbbb.i2p" in str(v) for v in entries)  # down-test has no DNS, uses b32

    def test_footer_has_timestamp(self, tmp_path: pathlib.Path):
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        assert "I2P Indexer Address Book" in content
        assert re.search(
            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}",
            content,
        ), "Footer missing generation date in YYYY-MM-DD HH:MM format"

    def test_creates_output_directory(self, tmp_path: pathlib.Path):
        db = _make_sample_db(tmp_path)
        nested = str(tmp_path / "deep" / "nested" / "dir")
        result = generate_address_book_html(db, nested)
        assert result.is_file()

    def test_html_contains_required_elements(self, tmp_path: pathlib.Path):
        """HTML contains tabs, timeline, filters, browse-table structure."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")

        # Tab structure
        assert 'data-tab="browse-table"' in content, "Missing browse table tab"
        assert 'data-tab="browse-timeline"' in content, "Missing timeline tab"
        # Filters
        assert 'id="filter-type"' in content, "Missing type filter"
        assert 'id="filter-lang"' in content, "Missing lang filter"
        assert 'id="filter-status"' in content, "Missing status filter"

    def test_embedded_json_row_count(self, tmp_path: pathlib.Path):
        """Embedded JSON contains all rows from address_book."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        entries = _extract_entries(content)
        assert len(entries) == 2, f"Expected 2 rows in JSON, got {len(entries)}"

    def test_json_reachable_flags(self, tmp_path: pathlib.Path):
        """Reachable entries have correct reachable boolean."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        entries = _extract_entries(content)
        by_dns = {row["dns_name"]: row for row in entries}
        assert by_dns["ok-test.i2p"]["reachable"] is True
        # down-test has no dns_name, so its key will be b32_addr
        assert any(not e["reachable"] for e in entries)

    def test_json_contains_detected_lang(self, tmp_path: pathlib.Path):
        """detected_lang field appears in every embedded JSON row."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        entries = _extract_entries(content)
        assert all("detected_lang" in e for e in entries)

    def test_json_contains_flags(self, tmp_path: pathlib.Path):
        """flags field appears in every embedded JSON row."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        entries = _extract_entries(content)
        assert all("flags" in e for e in entries)

    def test_json_contains_interest_fields(self, tmp_path: pathlib.Path):
        """Interest score, reasons, content_depth, stability_index in payload."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        entries = _extract_entries(content)
        assert all("interest_score" in e for e in entries)
        assert all("interest_reasons" in e for e in entries)
        assert all("content_depth" in e for e in entries)
        assert all("stability_index" in e for e in entries)

    def test_html_contains_lang_column(self, tmp_path: pathlib.Path):
        """Generated HTML includes language filtering."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        assert "detected_lang" in content, \
            "JS template missing detected_lang field reference"

    def test_empty_database_generates_valid_html(self, tmp_path: pathlib.Path):
        """Empty DB produces valid HTML with zero-row JSON."""
        db = _make_empty_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        assert result.is_file()
        content = result.read_text(encoding="utf-8")
        entries = _extract_entries(content)
        assert len(entries) == 0

    def test_timeline_data_present(self, tmp_path: pathlib.Path):
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        timeline = _extract_timeline(content)
        assert len(timeline) == 2

    def test_timeline_has_reachable_status(self, tmp_path: pathlib.Path):
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        timeline = _extract_timeline(content)
        reachables = {t["reachable"] for t in timeline}
        assert 1 in reachables  # ok-test is reachable
        assert 0 in reachables  # down-test is not


# ---------------------------------------------------------------------------
# Integration — generate_address_book_txt
# ---------------------------------------------------------------------------

class TestGenerateAddressBookTxt:
    def test_creates_file(self, tmp_path: pathlib.Path):
        db = _make_sample_db(tmp_path)
        result = generate_address_book_txt(db, str(tmp_path / "output"))
        assert result.is_file()
        assert result.name == "hosts.txt"

    def test_header_lines(self, tmp_path: pathlib.Path):
        db = _make_sample_db(tmp_path)
        result = generate_address_book_txt(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        assert "# Address book: I2P Indexer" in content
        assert "# Exported:" in content
        assert "# 2 entries" in content

    def test_contains_entries(self, tmp_path: pathlib.Path):
        db = _make_sample_db(tmp_path)
        result = generate_address_book_txt(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        assert "ok-test.i2p" in content
        assert "down-test.i2p" in content

    def test_entries_sorted_by_dns_name(self, tmp_path: pathlib.Path):
        db = _make_sample_db(tmp_path)
        result = generate_address_book_txt(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        lines = content.strip().split("\n")
        # Filter to value lines (non-comment)
        value_lines = [l for l in lines if not l.startswith("#")]
        dns_names = [l.split("=")[0] for l in value_lines]
        assert dns_names == sorted(dns_names, key=lambda x: x.lower())

    def test_value_line_format(self, tmp_path: pathlib.Path):
        db = _make_sample_db(tmp_path)
        result = generate_address_book_txt(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        lines = content.strip().split("\n")
        value_lines = [l for l in lines if not l.startswith("#")]
        # Each value line is dns_name=blob (or dns_name= when no blob)
        ok_line = [l for l in value_lines if "ok-test" in l][0]
        assert ok_line.startswith("ok-test.i2p=")
        down_line = [l for l in value_lines if "down-test" in l][0]
        assert down_line.startswith("down-test.i2p=")

    def test_creates_output_directory(self, tmp_path: pathlib.Path):
        db = _make_sample_db(tmp_path)
        nested = str(tmp_path / "deep" / "nested" / "dir")
        result = generate_address_book_txt(db, nested)
        assert result.is_file()

    def test_comment_contains_b32_reference(self, tmp_path: pathlib.Path):
        db = _make_sample_db(tmp_path)
        result = generate_address_book_txt(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        # Comment lines contain b32 address reference (b32_addr as stored in DB)
        assert "#ok-test.i2p: aaaaa.i2p" in content
        assert "#down-test.i2p: bbbbb.i2p" in content

    def test_each_entry_has_comment_and_value_lines(self, tmp_path: pathlib.Path):
        """Each destination produces exactly two lines: comment + value."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_txt(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        lines = content.strip().split("\n")
        # 3 header lines + 2 entries * 2 lines each = 7 lines
        assert len(lines) == 7

    def test_missing_b32_addr_empty_value(self, tmp_path: pathlib.Path):
        """Missing b32_addr produces empty value (nothing after =)."""
        from src.integration import DiscoveryDB

        db_path = str(tmp_path / "nob32.db")
        db = DiscoveryDB(db_path)
        # Record with empty b32_addr
        db.record_discovery(
            ident_hash_hex="cccccccccccccccccccccccccccccccccccccccc",
            b32_addr="",
            i2p_dns_name="no-b32-test.i2p",
            probe_mode="dns",
            reachable=True,
            status_code=200,
            body_length=512,
            title="No B32",
            response_time=2.0,
            via_method="https",
            content_type="web",
            content_summary="A page without b32 address",
        )
        db.close()

        result = generate_address_book_txt(db_path, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        lines = content.strip().split("\n")
        value_lines = [l for l in lines if not l.startswith("#")]
        assert len(value_lines) == 1
        # Value line should be "no-b32-test.i2p=" with nothing after the =
        assert value_lines[0] == "no-b32-test.i2p="

    def test_empty_database_txt(self, tmp_path: pathlib.Path):
        """Empty DB produces TXT with only 3 header lines."""
        db = _make_empty_db(tmp_path)
        result = generate_address_book_txt(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        lines = content.strip().split("\n")
        # Only the 3 header comment lines, no entries
        assert len(lines) == 3
        assert "# 0 entries" in content


# ---------------------------------------------------------------------------
# Detected lang roundtrip
# ---------------------------------------------------------------------------

class TestDetectedLangRoundtrip:
    def test_detected_lang_in_html_entries(self, tmp_path: pathlib.Path):
        """Language detection values survive roundtrip to HTML JSON."""
        from src.integration import DiscoveryDB

        db_path = str(tmp_path / "lang.db")
        db = DiscoveryDB(db_path)
        db.record_discovery(
            ident_hash_hex="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b32_addr="abcdefghijklmnopqrstuvwxyzaaaaa.b32.i2p",
            i2p_dns_name="de-site.i2p",
            probe_mode="dns",
            reachable=True,
            status_code=200,
            body_length=4096,
            title="German Site",
            response_time=1.5,
            via_method="https",
            content_type="blog",
            detected_lang="de",
            content_summary="Ein deutscher Blog",
        )
        db.record_discovery(
            ident_hash_hex="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            b32_addr="zzyyyyxxxxwwwwvvvvuuuuttttsssss.b32.i2p",
            i2p_dns_name="fr-site.i2p",
            probe_mode="dns",
            reachable=True,
            status_code=200,
            body_length=2048,
            title="French Site",
            response_time=2.0,
            via_method="https",
            content_type="web",
            detected_lang="fr",
            content_summary="Un site français",
        )
        db.close()

        result = generate_address_book_html(db_path, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        entries = _extract_entries(content)
        by_dns = {row["dns_name"]: row for row in entries}
        assert by_dns["de-site.i2p"]["detected_lang"] == "de"
        assert by_dns["fr-site.i2p"]["detected_lang"] == "fr"


# ---------------------------------------------------------------------------
# generate_index_html
# ---------------------------------------------------------------------------

class TestGenerateIndexHtml:
    def test_creates_file(self, tmp_path: pathlib.Path):
        from src.export_website import generate_index_html

        result = generate_index_html(str(tmp_path / "output"))
        assert result.is_file()
        assert result.name == "index.html"

    def test_contains_address_book_link(self, tmp_path: pathlib.Path):
        from src.export_website import generate_index_html

        result = generate_index_html(str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        assert 'href="address_book.html"' in content
        assert "Address Book" in content

    def test_contains_hosts_link(self, tmp_path: pathlib.Path):
        from src.export_website import generate_index_html

        result = generate_index_html(str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        assert 'href="hosts.txt"' in content

    def test_no_legacy_compact_link(self, tmp_path: pathlib.Path):
        """index.html should not contain address_book_ui.html or compact refs."""
        from src.export_website import generate_index_html

        result = generate_index_html(str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        assert "address_book_ui.html" not in content