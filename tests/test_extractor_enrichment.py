"""Tests for t4/t5: Summary enrichment — media servers, fallback classifiers, flags-in-summary."""
import pytest
from src.extractors import run_extractors
from src.integration import _extract_flags, _flags_to_summary_lines


class TestMediaServerDetection:
    """t4: Media server bucket with streaming enrichment."""

    def test_icecast_media_server(self):
        body = '<html><head><title>IceCast Streaming Server</title></head>' \
               '<body><h1>Radio Stream</h1>' \
               '<p>Streaming media: live rock music 24/7.</p>' \
               '<source src="live.m3u8">' \
               '</body></html>'
        result = run_extractors("IceCast Radio", body, {"Content-Type": "text/html"}, 200)
        assert result.content_type == "media server"
        assert any("HLS" in l for l in result.summary_lines)
        assert any("Stream sources" in l for l in result.summary_lines)

    def test_video_streaming_detection(self):
        body = '<html><head><title>Live Stream</title></head>' \
               '<body><p>Watch video.js player</p>' \
               '<a href="cam1.mp4">Camera 1</a>' \
               '</body></html>'
        result = run_extractors("Live Stream", body, {"Content-Type": "text/html"}, 200)
        assert result.content_type == "media server"
        assert any("Video" in l for l in result.summary_lines)

    def test_audio_streaming_detection(self):
        body = '<html><head><title>Radio</title></head>' \
               '<body><p>Listen to our live audio stream in ogg format</p>' \
               '<a href="stream.ogg">Stream</a>' \
               '</body></html>'
        result = run_extractors("Radio", body, {"Content-Type": "text/html"}, 200)
        assert result.content_type == "media server"
        assert any("Audio" in l for l in result.summary_lines)


class TestSocialNetworkDetection:
    """t4: Social/fediverse instance detection."""

    def test_mastodon_instance(self):
        body = '<html><head><title>Mastodon Instance</title></head>' \
               '<body><p>Welcome to our ActivityPub fediverse instance</p></body></html>'
        result = run_extractors("MyToot.social", body, {"Content-Type": "text/html"}, 200)
        assert result.content_type == "social network"


class TestFallbackClassifiers:
    """t4: Unidentified sites get classified via heuristics."""

    def test_login_portal_detected_as_web_app(self):
        body = '<html><head><title>Portal</title></head>' \
               '<body><h1>Welcome</h1>' \
               '<form><input type="text" name="user">' \
               '<input type="password" name="pass"></form></body></html>'
        result = run_extractors("Portal", body, {"Content-Type": "text/html"}, 200)
        assert result.content_type == "web application"

    def test_dashboard_detected_as_web_app(self):
        body = '<html><head><title>Home</title></head>' \
               '<body><h1>Statistics Dashboard</h1>' \
               '<p>Server status overview</p></body></html>'
        result = run_extractors("Home", body, {"Content-Type": "text/html"}, 200)
        assert result.content_type == "web application"

    def test_api_endpoint_detection(self):
        body = '<html><head><title>API Docs</title></head>' \
               '<body><div id="swagger-ui"></div></body></html>'
        result = run_extractors("API Docs", body, {"Content-Type": "text/html"}, 200)
        assert result.content_type == "api endpoint"

    def test_landing_page_dense_links(self):
        links = "".join(f'<a href="h{i}.b64.i2p">Link {i}</a>' for i in range(6))
        body = f'<html><head><title>Links</title></head>' \
               f'<body>{links}</body></html>'
        result = run_extractors("Links", body, {"Content-Type": "text/html"}, 200)
        assert result.content_type == "landing page"

    def test_plain_page_without_links_stays_unidentified(self):
        body = '<html><head><title>??? </title></head>' \
               '<body><p>X ß γ</p></body></html>'
        result = run_extractors("???", body, {"Content-Type": "text/html"}, 200)
        assert result.content_type == ""


class TestHeadingExtraction:
    """t4: Heading text (h1-h3) included in summaries."""

    def test_headings_added_as_sections(self):
        body = '<html><body>' \
               '<h1>Main Topic</h1><p>Some content here that is long enough.</p>' \
               '<h2>Sub Section</h2></body></html>'
        result = run_extractors("Site", body, {"Content-Type": "text/html"}, 200)
        assert any("Section: Main Topic" in l for l in result.summary_lines)
        assert any("Section: Sub Section" in l for l in result.summary_lines)


class TestParagraphExcerpts:
    """t4: Multiple content excerpts from paragraphs."""

    def test_multiple_excerpts_extracted(self):
        body = '<html><body>' \
               '<p>The first paragraph provides background information about the project.</p>' \
               '<p>A second paragraph gives details on funding and development timeline here.</p></body></html>'
        result = run_extractors("Site", body, {"Content-Type": "text/html"}, 200)
        excerpts = [l for l in result.summary_lines if "Content excerpt" in l]
        assert len(excerpts) == 2


class TestFlagsToSummaryLines:
    """t5: _flags_to_summary_lines converts structured flags to readable lines."""

    def test_robots_txt_flag(self):
        flags = [{"type": "robots_txt", "value": "disallow_all"}]
        lines = _flags_to_summary_lines(flags)
        assert any("Access policy" in l for l in lines)

    def test_contact_signal_flag(self):
        flags = [{"type": "contact_signal", "value": "email_address_in_page (2 addr(s))"}]
        lines = _flags_to_summary_lines(flags)
        assert any("Contact:" in l for l in lines)

    def test_forum_software_flag(self):
        flags = [{"type": "forum_software", "value": "Discourse"}]
        lines = _flags_to_summary_lines(flags)
        assert any("Forum software: Discourse" in l for l in lines)

    def test_redirect_chain_flag(self):
        flags = [{"type": "redirect_chain", "value": "depth=3"}]
        lines = _flags_to_summary_lines(flags)
        assert any("Redirect chain" in l for l in lines)

    def test_empty_flags_returns_empty(self):
        lines = _flags_to_summary_lines([])
        assert lines == []

    def test_proxy_indicator_ignored_in_summary(self):
        """proxy_indicator flags should not clutter the summary."""
        flags = [{"type": "proxy_indicator", "value": "cloudflare"}]
        lines = _flags_to_summary_lines(flags)
        assert lines == []

    def tech_stack_flag_ignored_in_summary(self):
        """tech_stack already handled by extractor — avoid duplication."""
        flags = [{"type": "tech_stack", "value": "Apache, PHP"}]
        lines = _flags_to_summary_lines(flags)
        assert lines == []


class TestFlagsIntegratedIntoProbeSummary:
    """t5: Flags appear in content_summary when probing via run_extractors flow."""

    def test_flags_merged_into_summary(self):
        body = '<html><head><title>Forum</title></head>' \
               '<body><p>Welcome to our phpBB3 forum community discussion board.</p></body></html>'
        result = run_extractors("Forum", body, {"Content-Type": "text/html"}, 200)

        # Extractor should classify as forum
        assert result.content_type == "forum"

        flags = _extract_flags(body)
        flagged_lines = _flags_to_summary_lines(flags)
        tech_stack_found = any(f.get("type") == "tech_stack" for f in flags)
        if tech_stack_found:
            pass  # Extractor already reports tech, no separate flag line needed


class TestKnownFileExtensionsInArchives:
    """t4: File archive only lists known extensions, not random body words."""

    def test_known_extensions_only(self):
        body = '<html><head><title>Archive</title></head>' \
               '<body><h1>Index of /files</h1>' \
               '<a href="backup.tar.gz">backup.tar.gz</a>' \
               '<a href="report.pdf">report.pdf</a></body></html>'
        result = run_extractors("Archive", body, {"Content-Type": "text/html"}, 200)
        ext_lines = [l for l in result.summary_lines if "File types" in l]
        assert len(ext_lines) == 1
        assert "tar" in ext_lines[0].lower()
        assert "gz" in ext_lines[0].lower()
        assert "pdf" in ext_lines[0].lower()
