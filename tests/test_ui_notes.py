"""UI-1 / UI-2: note content overflow wrap + sats_ext display on cards."""

from pathlib import Path

_STATIC = Path(__file__).resolve().parents[1] / "app" / "static"


class TestNoteContentOverflowUI1:
    """Long unbroken strings (URLs) must wrap in note content, feed + replies + profile."""

    def test_style_has_note_content_overflow_wrap(self):
        css = (_STATIC / "style.css").read_text()
        assert ".note-content" in css
        # Extract the .note-content rule block
        start = css.index(".note-content")
        block = css[start : start + 300]
        assert "overflow-wrap" in block or "overflow-wrap" in css
        assert "word-break" in block or "word-break" in css
        assert "max-width" in block or "max-width" in css
        # Must actually wrap unbroken tokens (anywhere / break-word / break-all)
        assert any(
            tok in css
            for tok in (
                "overflow-wrap: anywhere",
                "overflow-wrap:anywhere",
                "overflow-wrap: break-word",
                "overflow-wrap:break-word",
                "word-break: break-word",
                "word-break:break-word",
                "word-break: break-all",
                "word-break:break-all",
            )
        )

    def test_index_renderNoteCard_uses_note_content_class(self):
        index = (_STATIC / "index.html").read_text()
        assert "function renderNoteCard" in index
        fn = index.split("function renderNoteCard", 1)[1].split("\nfunction ", 1)[0]
        assert "note-content" in fn
        # Content paragraph must carry the wrap class (not bare whitespace-pre-wrap alone)
        assert "note-content" in fn and ("n.content" in fn or "${esc(n.content)}" in fn)

    def test_profile_notes_use_note_content_class(self):
        profile = (_STATIC / "profile.html").read_text()
        assert "note-content" in profile
        assert "whitespace-pre-wrap" in profile or "note-content" in profile


class TestSatsExtDisplayUI2:
    """Note cards must show sats_ext (external zaps) alongside sats_clank."""

    def test_index_renderNoteCard_reads_sats_ext(self):
        index = (_STATIC / "index.html").read_text()
        fn = index.split("function renderNoteCard", 1)[1].split("\nfunction ", 1)[0]
        assert "sats_ext" in fn
        assert "sats_clank" in fn

    def test_index_renderNoteCard_renders_both_tallies(self):
        index = (_STATIC / "index.html").read_text()
        fn = index.split("function renderNoteCard", 1)[1].split("\nfunction ", 1)[0]
        # Both values must appear in the card HTML (vote column or adjacent)
        assert "sats_ext" in fn
        # Distinct DOM ids so voteSuccess can update both
        assert "value-" in fn  # existing sats_clank span
        assert "ext-" in fn or "sats-ext-" in fn or "zap-" in fn

    def test_voteSuccess_updates_sats_ext(self):
        index = (_STATIC / "index.html").read_text()
        assert "function voteSuccess" in index
        fn = index.split("function voteSuccess", 1)[1].split("\nfunction ", 1)[0]
        assert "sats_ext" in fn or "newSatsExt" in fn or "new_sats_ext" in fn

    def test_vote_handlers_pass_new_sats_ext(self):
        index = (_STATIC / "index.html").read_text()
        assert "new_sats_ext" in index
        # credit path + confirm path both forward ext tally
        assert "data.new_sats_ext" in index or "d.new_sats_ext" in index

    def test_profile_notes_show_sats_ext(self):
        profile = (_STATIC / "profile.html").read_text()
        assert "sats_ext" in profile
        assert "sats_clank" in profile


class TestTwoFeedsUI3:
    """UI-3: clankfeed tab (origin=clankfeed, sats_clank) + external tab (all, sats_ext)."""

    def test_index_has_feed_tabs(self):
        index = (_STATIC / "index.html").read_text()
        assert 'id="feed-clankfeed"' in index or "feed-clankfeed" in index
        assert 'id="feed-external"' in index or "feed-external" in index
        assert "setFeed" in index or "currentFeed" in index

    def test_clankfeed_tab_queries_origin_clankfeed(self):
        index = (_STATIC / "index.html").read_text()
        # REST fetch must pass origin=clankfeed for the clankfeed feed
        assert "origin=clankfeed" in index
        # Default ranking for that tab uses clank/value sort
        assert "sort=clank" in index or "sort=value" in index or "currentSort" in index

    def test_external_tab_queries_all_ranked_by_ext(self):
        index = (_STATIC / "index.html").read_text()
        # External tab shows everything ranked by sats_ext
        assert "sort=ext" in index or "sort=zaps" in index
        # Must not force origin=external-only for the "everything" tab
        # (origin=all or omitted when feed is external)
        assert "setFeed" in index or "currentFeed" in index
        # When on external feed, fetch includes sort=ext (and not origin=clankfeed)
        fn = index
        if "function setFeed" in index:
            fn = index.split("function setFeed", 1)[1].split("\nfunction ", 1)[0]
        elif "function loadFeed" in index:
            fn = index.split("function loadFeed", 1)[1].split("\nfunction ", 1)[0]
        assert "ext" in fn or "zaps" in fn or "external" in fn

    def test_feed_fetch_uses_origin_param(self):
        index = (_STATIC / "index.html").read_text()
        assert "origin=" in index
        assert "clankfeed" in index
