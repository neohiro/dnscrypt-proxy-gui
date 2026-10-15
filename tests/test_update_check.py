"""Tests for the update checker's version semantics and failure contract."""
import sys
import types

import pytest

from conftest import mod


class TestParseSemver:
    @pytest.mark.parametrize("tag,expected", [
        ("v1.2.3", (1, 2, 3)),
        ("1.2.3", (1, 2, 3)),
        ("V2.0.0", (2, 0, 0)),
        ("v1.2.3-beta.1", (1, 2, 3)),
        ("v1.2.3+build.7", (1, 2, 3)),
        (" v1.0.5 ", (1, 0, 5)),
        ("v01.02.03", (1, 2, 3)),
    ])
    def test_valid_tags(self, tag, expected):
        assert mod.DNSCryptClientGUI._parse_semver(tag) == expected

    @pytest.mark.parametrize("bad", ["", "latest", "v1.2", "v1.2.3.4",
                                     "version-1.2.3", "v1.x.3", None, 42])
    def test_malformed_tags_return_none(self, bad):
        assert mod.DNSCryptClientGUI._parse_semver(bad) is None


class TestEvaluateUpdate:
    CURRENT = "1.1.0"

    @pytest.mark.parametrize("remote", ["v1.1.1", "v1.2.0", "v2.0.0"])
    def test_remote_newer_is_available(self, remote):
        kind, display, url = mod.DNSCryptClientGUI._evaluate_update(
            remote, self.CURRENT)
        assert kind == "available"
        assert display == remote  # 'v'-prefixed, as shown in the UI
        assert url.endswith("/releases/latest")

    def test_equal_is_current(self):
        kind, display, _ = mod.DNSCryptClientGUI._evaluate_update("v1.1.0", self.CURRENT)
        assert kind == "current"
        assert display == "v1.1.0"

    @pytest.mark.parametrize("remote", ["v1.0.9", "v1.0.5", "v0.9.9"])
    def test_remote_older_is_current(self, remote):
        kind, _, _ = mod.DNSCryptClientGUI._evaluate_update(remote, self.CURRENT)
        assert kind == "current"

    def test_component_wise_comparison_not_stringwise(self):
        # String comparison would rank "v1.10.0" below "v1.9.0"; semver must not.
        kind, display, _ = mod.DNSCryptClientGUI._evaluate_update("v1.10.0", "1.9.0")
        assert kind == "available"
        assert display == "v1.10.0"

    @pytest.mark.parametrize("garbage", [None, "", "oops", "v1.2"])
    def test_unparseable_remote_is_invalid(self, garbage):
        kind, display, _ = mod.DNSCryptClientGUI._evaluate_update(garbage, self.CURRENT)
        assert kind == "invalid"
        assert display == ""

    def test_prerelease_of_same_base_is_not_a_downgrade(self):
        # We never ship pre-releases; same base with a suffix counts as current.
        kind, _, _ = mod.DNSCryptClientGUI._evaluate_update("v1.1.0-rc1", self.CURRENT)
        assert kind == "current"


class TestFetchFailureContract:
    def test_network_error_yields_none_pair(self, gui, monkeypatch):
        def boom(*args, **kwargs):
            raise OSError("network unreachable")

        fake_requests = types.SimpleNamespace(get=boom)
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        tag, url = gui._fetch_latest_release()
        assert tag is None and url is None

    def test_fetch_release_with_etag_network_error(self, gui, monkeypatch):
        """Network failure in _fetch_release_with_etag must return (None, None)."""
        def boom(*args, **kwargs):
            raise OSError("connection refused")

        fake_requests = types.SimpleNamespace(get=boom)
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        tag, url = gui._fetch_release_with_etag(
            "https://api.github.com/repos/foo/bar/releases/latest",
            "https://example.com/fallback",
            etag_attr="_gui_release_etag",
            cache_tag_attr="_gui_cached_release_tag",
            cache_url_attr="_gui_cached_release_url",
            log_label="Test",
        )
        assert tag is None and url is None

    def test_unexpected_payload_yields_none_pair(self, gui, monkeypatch):
        class FakeResponse:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return "not-a-dict"

        fake_requests = types.SimpleNamespace(
            get=lambda *a, **k: FakeResponse())
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        tag, url = gui._fetch_latest_release()
        assert tag is None and url is None

    def test_success_returns_tag_and_url(self, gui, monkeypatch):
        class FakeResponse:
            status_code = 200
            headers = {"ETag": ""}  # noqa: RUF012

            def raise_for_status(self):
                pass

            def json(self):
                return {"tag_name": "v1.2.1",
                        "html_url": "https://github.com/neohiro/dnscrypt-proxy-gui/releases/tag/v1.2.1"}

        fake_requests = types.SimpleNamespace(
            get=lambda *a, **k: FakeResponse())
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        tag, url = gui._fetch_latest_release()
        assert tag == "v1.2.1"
        assert url == "https://github.com/neohiro/dnscrypt-proxy-gui/releases/tag/v1.2.1"

    def test_non_string_html_url_falls_back(self, gui, monkeypatch):
        class FakeResponse:
            status_code = 200
            headers = {"ETag": ""}  # noqa: RUF012

            def raise_for_status(self):
                pass

            def json(self):
                return {"tag_name": "v1.2.1", "html_url": ["nonsense"]}

        fake_requests = types.SimpleNamespace(
            get=lambda *a, **k: FakeResponse())
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        tag, url = gui._fetch_latest_release()
        assert tag == "v1.2.1"
        # Lists are not valid URLs; _safe_url falls back.
        assert url == "https://github.com/neohiro/dnscrypt-proxy-gui/releases/latest"

    def test_304_returns_cached_tag_and_url(self, gui, monkeypatch):
        class Fake304:
            status_code = 304

            def raise_for_status(self):
                pass

        class Fake200:
            status_code = 200
            headers = {"ETag": '"abc123"'}  # noqa: RUF012

            def raise_for_status(self):
                pass

            def json(self):
                return {"tag_name": "v1.2.1",
                        "html_url": "https://github.com/neohiro/dnscrypt-proxy-gui/releases/tag/v1.2.1"}

        call_count = [0]

        def fake_get(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return Fake200()
            return Fake304()

        fake_requests = types.SimpleNamespace(get=fake_get)
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        tag1, url1 = gui._fetch_latest_release()
        assert tag1 == "v1.2.1"
        assert url1 == "https://github.com/neohiro/dnscrypt-proxy-gui/releases/tag/v1.2.1"
        assert gui._gui_release_etag == '"abc123"'
        tag2, url2 = gui._fetch_latest_release()
        assert tag2 == "v1.2.1"
        assert url2 == "https://github.com/neohiro/dnscrypt-proxy-gui/releases/tag/v1.2.1"
        assert call_count == [2]

    def test_304_without_prior_cache_falls_through(self, gui, monkeypatch):
        class Fake304:
            status_code = 304

            def raise_for_status(self):
                pass

        class Fake200:
            status_code = 200
            headers = {"ETag": '"xyz789"'}  # noqa: RUF012

            def raise_for_status(self):
                pass

            def json(self):
                return {"tag_name": "v1.2.2",
                        "html_url": "https://github.com/neohiro/dnscrypt-proxy-gui/releases/tag/v1.2.2"}

        call_count = [0]

        def fake_get(url, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return Fake304()
            return Fake200()

        fake_requests = types.SimpleNamespace(get=fake_get)
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        # No cached tag/url yet; 304 should trigger a re-fetch.
        tag, _ = gui._fetch_latest_release()
        assert tag == "v1.2.2"
        assert call_count == [2]
