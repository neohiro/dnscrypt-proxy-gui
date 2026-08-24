"""Tests for the resolver/relay markdown list parser."""
import os

import pytest

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _read_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return fh.read()


class TestSyntheticParsing:
    def test_empty_text_returns_empty(self, gui):
        assert gui._parse_markdown_list("") == []

    def test_entry_with_stamp_is_parsed(self, gui):
        text = "## My Server\n\nA test resolver.\n\nsdns://AQcAAAAAAAAABzEuMi4zLjQ\n"
        data = gui._parse_markdown_list(text)
        assert len(data) == 1
        assert data[0]["name"] == "My Server"
        assert data[0]["stamp"] == "sdns://AQcAAAAAAAAABzEuMi4zLjQ"

    def test_entry_without_stamp_is_skipped(self, gui):
        text = "## Broken Server\n\nNo stamp here.\n"
        assert gui._parse_markdown_list(text) == []

    def test_description_captured_before_stamp(self, gui):
        text = "## S\n\nfirst line\nsecond line\nsdns://AQcAAAAAAAAAAQ\n"
        (entry,) = gui._parse_markdown_list(text)
        assert "first line" in entry["description"]
        assert "second line" in entry["description"]

    def test_first_stamp_wins(self, gui):
        text = "## S\n\nsdns://AAAAFIRST\nsdns://BBBBSECOND\n"
        (entry,) = gui._parse_markdown_list(text)
        assert entry["stamp"] == "sdns://AAAAFIRST"

    def test_multiple_entries(self, gui):
        text = (
            "## One\nsdns://AAAAAAAAAA\n"
            "## Two\nsdns://BBBBBBBBBB\n"
            "## Three\nno stamp\n"
            "## Four\nsdns://CCCCCCCCCC\n"
        )
        data = gui._parse_markdown_list(text)
        assert [d["name"] for d in data] == ["One", "Two", "Four"]


class TestFixtureParsing:
    """Parse the real upstream lists to guard against format drift."""

    @pytest.mark.parametrize(
        "fixture_name", ["public-resolvers.md", "relays.md"]
    )
    def test_real_lists_parse(self, gui, fixture_name):
        data = gui._parse_markdown_list(_read_fixture(fixture_name))
        assert len(data) > 10, f"{fixture_name}: suspiciously few entries parsed"
        for entry in data:
            assert entry["stamp"].startswith("sdns://"), entry["name"]
            assert entry["name"].strip() == entry["name"]

    def test_resolver_names_are_unique(self, gui):
        names = [s["name"] for s in gui._parse_markdown_list(_read_fixture("public-resolvers.md"))]
        assert len(names) == len(set(names))
