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
