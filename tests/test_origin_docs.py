"""UI3.3: public docs must advertise GET /api/v1/events?origin= and response origin."""

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_API_MD = (_ROOT / "docs" / "API.md").read_text()
_README = (_ROOT / "README.md").read_text()


class TestOriginDiscoveryDocsUI33:
    """Agents reading API.md/README must discover the dual-feed origin filter."""

    def test_api_md_documents_origin_query_param(self):
        """GET /api/v1/events query-param table lists origin=clankfeed|external|all."""
        assert "### Read Notes" in _API_MD or "`GET /api/v1/events`" in _API_MD
        # Param table row (or equivalent) for origin
        assert "`origin`" in _API_MD
        assert "clankfeed" in _API_MD
        assert "external" in _API_MD
        # All three allowed values appear near the origin docs
        origin_idx = _API_MD.index("`origin`")
        window = _API_MD[origin_idx : origin_idx + 400]
        assert "clankfeed" in window
        assert "external" in window
        assert "all" in window

    def test_api_md_response_includes_origin_field(self):
        """Event objects in the GET /api/v1/events response example include origin."""
        # Find the Read Notes / GET events response example
        read_start = _API_MD.index("#### `GET /api/v1/events`")
        # Next #### section bounds the response example
        next_section = _API_MD.find("#### `GET /api/v1/events/{event_id}`", read_start)
        section = _API_MD[read_start:next_section]
        assert '"origin"' in section or "`origin`" in section
        # Values agents should expect
        assert "clankfeed" in section or "external" in section

    def test_readme_mentions_origin_feed_filter(self):
        """README ranking/feed notes mention origin query for dual feeds."""
        # Must advertise as a query filter (not a bare CORS "origin" word)
        assert "origin=" in _README
        assert "clankfeed" in _README.lower()
        assert "external" in _README.lower()
        # Tie to the events endpoint; prefer the dual-feed line over the early How-it-works stub
        assert "/api/v1/events?origin=" in _README or (
            "/api/v1/events" in _README and "`origin`" in _README
        )
        # Dual-feed values agents must pass
        dual = _README
        # Find the Dual feeds / origin section (or fall back to any origin= line)
        if "## Dual feeds" in dual:
            start = dual.index("## Dual feeds")
            section = dual[start : start + 600]
        else:
            start = dual.index("origin=")
            section = dual[max(0, start - 100) : start + 400]
        assert "clankfeed" in section
        assert "external" in section
        assert "all" in section
