"""Tests for structured logging helpers and is_admin caching."""
import logging
import platform

import pytest

import sys
sys.path.insert(0, 'tests')
import conftest


@pytest.fixture
def g():
    return conftest.make_gui()


# ------------------ Structured logging ------------------

def test_structured_log_emits_event_and_kwargs(caplog, g):
    with caplog.at_level(logging.INFO, "DNSCryptClientGUI"):
        g._structured_log("dns_activation_start", server_count=3)
    assert len(caplog.records) == 1
    msg = caplog.records[0].getMessage()
    assert "dns_activation_start" in msg
    assert "server_count" in msg


def test_structured_log_omits_kwargs_section_when_empty(caplog, g):
    with caplog.at_level(logging.INFO, "DNSCryptClientGUI"):
        g._structured_log("ping")
    assert len(caplog.records) == 1
    msg = caplog.records[0].getMessage()
    assert "ping" in msg


def test_structured_log_coerces_non_primitives(caplog, g):
    class _Weird:
        def __repr__(self):
            return "<Weird:42>"

    payload = {"list": [1, 2, 3], "obj": _Weird(), "tup": ("a", "b")}
    with caplog.at_level(logging.INFO, "DNSCryptClientGUI"):
        g._structured_log("ev", **payload)
    msg = caplog.records[0].getMessage()
    # Format is "key: value" (quoted via repr for non-primitives)
    assert "'list': '[1, 2, 3]'" in msg
    assert "'obj': '<Weird:42>'" in msg
    assert "'tup': \"('a', 'b')\"" in msg


def test_log_dns_activation_start_includes_server_count(caplog, g):
    with caplog.at_level(logging.INFO, "DNSCryptClientGUI"):
        g._log_dns_activation_start(5)
    assert len(caplog.records) == 1
    msg = caplog.records[0].getMessage()
    assert "dns_activation_start" in msg
    assert "5" in msg


def test_log_dns_activation_success_includes_duration(caplog, g):
    with caplog.at_level(logging.INFO, "DNSCryptClientGUI"):
        g._log_dns_activation_success(2, 0.123)
    assert len(caplog.records) == 1
    msg = caplog.records[0].getMessage()
    assert "dns_activation_success" in msg
    assert "duration_s" in msg


def test_log_dns_activation_failure_includes_reason(caplog, g):
    with caplog.at_level(logging.INFO, "DNSCryptClientGUI"):
        g._log_dns_activation_failure(2, "set_system_dns_failed")
    assert len(caplog.records) == 1
    msg = caplog.records[0].getMessage()
    assert "dns_activation_failure" in msg
    assert "set_system_dns_failed" in msg


def test_log_dns_deactivation_start(caplog, g):
    with caplog.at_level(logging.INFO, "DNSCryptClientGUI"):
        g._log_dns_deactivation_start()
    assert len(caplog.records) == 1
    assert "dns_deactivation_start" in caplog.records[0].getMessage()


def test_log_dns_deactivation_success(caplog, g):
    with caplog.at_level(logging.INFO, "DNSCryptClientGUI"):
        g._log_dns_deactivation_success()
    assert len(caplog.records) == 1
    assert "dns_deactivation_success" in caplog.records[0].getMessage()


# ------------------ is_admin caching ------------------

def _reset_is_admin_cache():
    if hasattr(conftest.mod.is_admin, "_cached_result"):
        del conftest.mod.is_admin._cached_result


@pytest.mark.skipif(platform.system() == "Windows", reason="os.geteuid not available on Windows")
def test_is_admin_posix_cache_persists(monkeypatch):
    _reset_is_admin_cache()
    call_count = {"n": 0}

    def counting_geteuid():
        call_count["n"] += 1
        return 0

    monkeypatch.setattr(conftest.mod.os, "geteuid", counting_geteuid)
    conftest.mod.is_admin()
    conftest.mod.is_admin()
    conftest.mod.is_admin()
    assert call_count["n"] == 1


def test_is_admin_caches_result_on_subsequent_calls():
    _reset_is_admin_cache()
    conftest.mod.is_admin()
    assert hasattr(conftest.mod.is_admin, "_cached_result")


def test_is_admin_transient_failure_does_not_cache(monkeypatch):
    _reset_is_admin_cache()
    if platform.system() == "Windows":
        import ctypes
        call_count = {"n": 0}

        def broken_IsUserAnAdmin():
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise OSError("simulated transient failure")
            return 1

        orig = ctypes.windll.shell32.IsUserAnAdmin
        ctypes.windll.shell32.IsUserAnAdmin = broken_IsUserAnAdmin
        try:
            assert conftest.mod.is_admin() is False
            assert conftest.mod.is_admin() is True
        finally:
            ctypes.windll.shell32.IsUserAnAdmin = orig
    else:
        call_count = {"n": 0}

        def broken_geteuid():
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise OSError("simulated transient failure")
            return 0

        monkeypatch.setattr(conftest.mod.os, "geteuid", broken_geteuid)
        assert conftest.mod.is_admin() is False
        assert conftest.mod.is_admin() is True
