"""Tests for src.export_website — HTML and TXT generators."""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from src.export_website import (
    _format_response_time,
    _humanize_bytes,
    _transform_row,
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


def _extract_json(html: str) -> list[dict]:
    """Pull the embedded DATA array out of generated HTML and parse it."""
    # The template contains: const DATA = [...];
    start = html.index("const DATA = ") + len("const DATA = ")
    # Find the closing semicolon after the array literal
    end = html.index(";", start)
    raw = html[start:end]
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Helpers — unit
# ---------------------------------------------------------------------------

class TestHumanizeBytes:
    def test_none(self):
        assert _humanize_bytes(None) == ""

    def test_zero(self):
        assert _humanize_bytes(0) == ""

    def test_bytes(self):
        assert _humanize_bytes(49) == "49B"

    def test_kilobytes(self):
        assert _humanize_bytes(1024) == "1.0KB"
        assert _humanize_bytes(41881) == "40.9KB"

    def test_megabytes(self):
        mb = 1024 * 1024
        assert _humanize_bytes(mb) == "1.0MB"


class TestFormatResponseTime:
    def test_none(self):
        assert _format_response_time(None) == ""

    def test_zero(self):
        assert _format_response_time(0.0) == ""

    def test_value(self):
        assert _format_response_time(6.37) == "6.4s"


class TestTransformRow:
    def test_reachable_with_data(self):
        row = {
            "dns_name": "test.i2p",
            "title": "Test",
            "content_type": "blog",
            "content_summary": "summary",
            "reachable": True,
            "last_probed_utc": "2026-08-01 00:00:00",
            "response_time_sec": 3.0,
            "body_length": 1024,
            "bandwidth_kbps": 50,
            "found_links": '["a.i2p"]',
        }
        out = _transform_row(row)
        assert out["_rt"] == "3.0s"
        assert out["_size"] == "1.0KB"
        assert out["content_summary"] == "summary"

    def test_empty_fields_become_unidentified(self):
        row = {
            "dns_name": "bad.i2p",
            "reachable": False,
            "response_time_sec": 0,
            "body_length": 0,
            "content_summary": "",
            "found_links": None,
        }
        out = _transform_row(row)
        assert out["content_summary"] == "Unidentified"
        assert out["_rt"] == ""
        assert out["_size"] == ""
        assert out["found_links"] == "[]"


# ---------------------------------------------------------------------------
# Integration — generate_address_book_html
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
        assert "ok-test.i2p" in content
        assert "down-test.i2p" in content

    def test_footer_has_timestamp(self, tmp_path: pathlib.Path):
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        # Footer should have a YYYY-MM-DD HH:MM timestamp
        assert "I2P Indexer Address Book" in content
        # Timestamp format: 2026-08-03 19:00
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
        """HTML contains <script>, DATA array, stats bar, grid table."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")

        # Script tag present
        assert "<script>" in content, "Missing <script> tag"
        # DATA array embedded
        assert "const DATA = " in content, "Missing DATA array"
        # Stats bar div
        assert 'class="stats"' in content, "Missing stats bar"
        # Grid table with head and body
        assert 'id="grid"' in content, "Missing grid table"
        assert 'id="head"' in content, "Missing thead container"
        assert 'id="body"' in content, "Missing tbody container"

    def test_embedded_json_row_count(self, tmp_path: pathlib.Path):
        """Embedded JSON contains all rows from address_book."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        data = _extract_json(content)
        # We inserted 2 destinations
        assert len(data) == 2, f"Expected 2 rows in JSON, got {len(data)}"

    def test_json_status_ok_vs_down(self, tmp_path: pathlib.Path):
        """Reachable entries get _status='OK', unreachable get 'DOWN'."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        data = _extract_json(content)
        # The JS computes _status at runtime from the 'reachable' field.
        # Check that the JSON payload has the correct reachable flags:
        by_dns = {row["dns_name"]: row for row in data}
        assert by_dns["ok-test.i2p"]["reachable"] is True
        assert by_dns["down-test.i2p"]["reachable"] is False

    def test_json_response_time_formatted(self, tmp_path: pathlib.Path):
        """response_time_sec is formatted as 'X.Xs' in embedded JSON."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        data = _extract_json(content)
        by_dns = {row["dns_name"]: row for row in data}
        # ok-test has response_time=1.5 → "1.5s"
        assert by_dns["ok-test.i2p"]["_rt"] == "1.5s"
        # down-test has response_time=60.2 → "60.2s"
        assert by_dns["down-test.i2p"]["_rt"] == "60.2s"

    def test_json_body_length_humanized(self, tmp_path: pathlib.Path):
        """body_length is humanized (e.g. '4.0KB') in embedded JSON."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        data = _extract_json(content)
        by_dns = {row["dns_name"]: row for row in data}
        # ok-test has body_length=4096 → "4.0KB"
        assert by_dns["ok-test.i2p"]["_size"] == "4.0KB"
        # down-test has body_length=0 → ""
        assert by_dns["down-test.i2p"]["_size"] == ""

    def test_json_none_fields_become_empty_string(self, tmp_path: pathlib.Path):
        """None/null fields become empty string in JSON payload."""
        from src.export_website import _transform_row

        row = {
            "dns_name": None,
            "title": None,
            "content_type": None,
            "content_summary": None,
            "reachable": False,
            "last_probed_utc": None,
            "response_time_sec": 0,
            "body_length": 0,
            "bandwidth_kbps": None,
            "found_links": None,
        }
        out = _transform_row(row)
        assert out["dns_name"] == ""
        assert out["title"] == ""
        assert out["content_type"] == ""
        assert out["last_probed_utc"] == ""

    def test_empty_database_generates_valid_html(self, tmp_path: pathlib.Path):
        """Empty DB produces valid HTML with zero-row JSON."""
        db = _make_empty_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        assert result.is_file()
        content = result.read_text(encoding="utf-8")
        data = _extract_json(content)
        assert len(data) == 0
        # HTML size is reasonable (template overhead < 10KB)
        assert result.stat().st_size < 10_000

    def test_html_size_reasonable(self, tmp_path: pathlib.Path):
        """Generated HTML file size stays under 1MB for typical datasets."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        # 2 entries should be well under 100KB
        assert result.stat().st_size < 1_000_000

    def test_embedded_json_contains_detected_lang(self, tmp_path: pathlib.Path):
        """detected_lang field appears in every embedded JSON row."""
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
        data = _extract_json(content)
        assert len(data) == 2
        by_dns = {row["dns_name"]: row for row in data}
        assert by_dns["de-site.i2p"]["detected_lang"] == "de"
        assert by_dns["fr-site.i2p"]["detected_lang"] == "fr"

    def test_html_contains_lang_column_header(self, tmp_path: pathlib.Path):
        """Generated HTML JS includes 'Language' column in COLS array."""
        db = _make_sample_db(tmp_path)
        result = generate_address_book_html(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        assert "'Language'" in content or '"Language"' in content, \
            "COLS array missing Language column label"
        assert "detected_lang" in content, \
            "JS template missing detected_lang field reference"


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

    def test_detected_lang_in_transform_row(self, tmp_path: pathlib.Path):
        """detected_lang from address_book view passes through _transform_row."""
        row = {
            "dns_name": "test.i2p",
            "title": "Test",
            "content_type": "blog",
            "content_summary": "summary",
            "detected_lang": "de",
            "reachable": True,
            "last_probed_utc": "2026-08-01 00:00:00",
            "response_time_sec": 3.0,
            "body_length": 1024,
            "bandwidth_kbps": 50,
            "found_links": '["a.i2p"]',
        }
        from src.export_website import _transform_row

        out = _transform_row(row)
        assert out["detected_lang"] == "de"

    def test_detected_lang_empty_becomes_empty_string(self, tmp_path: pathlib.Path):
        """Missing detected_lang becomes empty string in transform."""
        from src.export_website import _transform_row

        row = {
            "dns_name": "test.i2p",
            "detected_lang": None,
            "reachable": True,
            "response_time_sec": 0,
            "body_length": 0,
        }
        out = _transform_row(row)
        assert out["detected_lang"] == ""

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
# Helpers — enhanced UI (generate_address_book_ui)
# ---------------------------------------------------------------------------

def _make_ui_db(tmp_path: pathlib.Path):
    """Create a fresh DB with sample data for the enhanced browse UI."""
    from src.integration import DiscoveryDB

    db = DiscoveryDB(str(tmp_path / "ui_test.db"))
    db.record_discovery(
        ident_hash_hex="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        b32_addr="abcdefghijklmnopqrstuvwxyzaaaaa.b32.i2p",
        i2p_dns_name="site-a.i2p",
        probe_mode="dns",
        reachable=True,
        status_code=200,
        body_length=4096,
        title="Site A",
        response_time=1.5,
        via_method="https",
        content_type="blog",
        detected_lang="de",
        content_summary="A German blog about I2P",
        found_links=["site-b.i2p"],
    )
    db.record_discovery(
        ident_hash_hex="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        b32_addr="zzyyyyxxxxwwwwvvvvuuuuttttsssss.b32.i2p",
        i2p_dns_name="",
        probe_mode="dns",
        reachable=False,
        status_code=0,
        body_length=0,
        title="",
        response_time=60.0,
        via_method="https",
        content_type="",
        detected_lang="",
        content_summary="",
    )
    db.close()
    return str(tmp_path / "ui_test.db")


def _extract_entries(html: str) -> list[dict]:
    """Pull the embedded ENTRIES array out of enhanced UI HTML."""
    start = html.index("const ENTRIES  = ") + len("const ENTRIES  = ")
    end = html.index(";", start)
    raw = html[start:end]
    return json.loads(raw)


def _extract_timeline(html: str) -> list[dict]:
    """Pull the embedded TIMELINE array out of enhanced UI HTML."""
    start = html.index("const TIMELINE = ") + len("const TIMELINE = ")
    end = html.index(";", start)
    raw = html[start:end]
    return json.loads(raw)


class TestGenerateAddressBookUI:
    def test_creates_file(self, tmp_path: pathlib.Path):
        from src.export_website import generate_address_book_ui

        db = _make_ui_db(tmp_path)
        result = generate_address_book_ui(db, str(tmp_path / "output"))
        assert result.is_file()
        assert result.name == "address_book_ui.html"

    def test_contains_entries_data(self, tmp_path: pathlib.Path):
        from src.export_website import generate_address_book_ui

        db = _make_ui_db(tmp_path)
        result = generate_address_book_ui(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        entries = _extract_entries(content)
        assert len(entries) == 2

    def test_entries_include_detected_lang(self, tmp_path: pathlib.Path):
        from src.export_website import generate_address_book_ui

        db = _make_ui_db(tmp_path)
        result = generate_address_book_ui(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        entries = _extract_entries(content)
        by_dns = {e["dns_name"]: e for e in entries}
        assert by_dns["site-a.i2p"]["detected_lang"] == "de"
        # Second entry has no dns_name, so its dns_name will be b32_addr from view
        assert entries[1]["detected_lang"] == ""

    def test_entries_include_flags(self, tmp_path: pathlib.Path):
        from src.export_website import generate_address_book_ui

        db = _make_ui_db(tmp_path)
        result = generate_address_book_ui(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        entries = _extract_entries(content)
        assert all("flags" in e for e in entries)

    def test_entries_contains_site_names(self, tmp_path: pathlib.Path):
        from src.export_website import generate_address_book_ui

        db = _make_ui_db(tmp_path)
        result = generate_address_book_ui(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        assert "site-a.i2p" in content

    def test_timeline_data_present(self, tmp_path: pathlib.Path):
        from src.export_website import generate_address_book_ui

        db = _make_ui_db(tmp_path)
        result = generate_address_book_ui(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        timeline = _extract_timeline(content)
        assert len(timeline) == 2

    def test_timeline_has_reachable_status(self, tmp_path: pathlib.Path):
        from src.export_website import generate_address_book_ui

        db = _make_ui_db(tmp_path)
        result = generate_address_book_ui(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        timeline = _extract_timeline(content)
        reachables = {t["reachable"] for t in timeline}
        assert 1 in reachables  # site-a is reachable
        assert 0 in reachables  # b32-only entry is not

    def test_html_has_tabs(self, tmp_path: pathlib.Path):
        from src.export_website import generate_address_book_ui

        db = _make_ui_db(tmp_path)
        result = generate_address_book_ui(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        assert 'data-tab="browse-table"' in content
        assert 'data-tab="browse-timeline"' in content

    def test_html_has_filters(self, tmp_path: pathlib.Path):
        from src.export_website import generate_address_book_ui

        db = _make_ui_db(tmp_path)
        result = generate_address_book_ui(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        assert 'id="filter-type"' in content
        assert 'id="filter-lang"' in content
        assert 'id="filter-status"' in content

    def test_html_has_timeline_elements(self, tmp_path: pathlib.Path):
        from src.export_website import generate_address_book_ui

        db = _make_ui_db(tmp_path)
        result = generate_address_book_ui(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        assert 'id="tl-body"' in content
        assert 'id="tl-filter"' in content

    def test_empty_database_ui(self, tmp_path: pathlib.Path):
        from src.export_website import generate_address_book_ui

        db = _make_empty_db(tmp_path)
        result = generate_address_book_ui(db, str(tmp_path / "output"))
        assert result.is_file()
        content = result.read_text(encoding="utf-8")
        entries = _extract_entries(content)
        assert len(entries) == 0
        timeline = _extract_timeline(content)
        assert len(timeline) == 0

    def test_creates_output_directory(self, tmp_path: pathlib.Path):
        from src.export_website import generate_address_book_ui

        db = _make_ui_db(tmp_path)
        nested = str(tmp_path / "deep" / "nested" / "ui")
        result = generate_address_book_ui(db, nested)
        assert result.is_file()

    def test_footer_has_timestamp(self, tmp_path: pathlib.Path):
        from src.export_website import generate_address_book_ui

        db = _make_ui_db(tmp_path)
        result = generate_address_book_ui(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        assert "I2P Indexer Address Book" in content
        assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", content), \
            "Footer missing generation date"

    def test_entry_reachable_flags(self, tmp_path: pathlib.Path):
        from src.export_website import generate_address_book_ui

        db = _make_ui_db(tmp_path)
        result = generate_address_book_ui(db, str(tmp_path / "output"))
        content = result.read_text(encoding="utf-8")
        entries = _extract_entries(content)
        by_dns = {e["dns_name"]: e for e in entries}
        assert by_dns["site-a.i2p"]["reachable"] is True
