"""Tests for autostart registration helpers, DNS backup policy and settings."""
import json
import os
import platform
import sys
import threading

import pytest
from conftest import make_gui


def _fake_which(monkeypatch, return_value):
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda name: return_value)


class TestStartupTokens:
    def test_script_mode_lists_interpreter_and_script(self, gui):
        tokens = gui.get_startup_tokens()
        assert tokens == [sys.executable, os.path.abspath(sys.argv[0])]

    def test_frozen_mode_launches_executable_alone(self, gui, monkeypatch):
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        assert gui.get_startup_tokens() == [sys.executable]


class TestQuotingHelpers:
    def test_desktop_quote_escapes_specials(self, gui):
        quoted = gui._desktop_quote('/home/u "my dir"')
        assert quoted == '"/home/u \\"my dir\\""'

    def test_desktop_quote_escapes_field_codes(self, gui):
        assert gui._desktop_quote("app%U") == '"app%%U"'

    def test_xml_escape(self, gui):
        assert gui._xml_escape('a & b<c>') == "a &amp; b&lt;c&gt;"


class TestRestorePolicy:
    def _write_backup(self, path, platform_name="Windows"):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"platform": platform_name}, fh)

    def test_full_restore_deletes_backup(self, gui, tmp_path, monkeypatch):
        backup = tmp_path / "dns_backup.json"
        self._write_backup(str(backup))
        gui.dns_backup_file = str(backup)
        monkeypatch.setattr(gui.__class__, "_restore_dns_windows", lambda self, snap: [])
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        assert gui.restore_dns_backup() is True
        assert not backup.exists()

    def test_partial_failure_keeps_backup_for_retry(self, gui, tmp_path, monkeypatch):
        backup = tmp_path / "dns_backup.json"
        self._write_backup(str(backup))
        gui.dns_backup_file = str(backup)
        monkeypatch.setattr(gui.__class__, "_restore_dns_windows",
                            lambda self, snap: ["Ethernet"])
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        assert gui.restore_dns_backup() is False
        assert backup.exists(), "partial failure must keep the backup retryable"

    def test_revert_helper_ignores_dhcp_reset_when_backup_remains(
            self, gui, tmp_path, monkeypatch):
        backup = tmp_path / "dns_backup.json"
        self._write_backup(str(backup))
        gui.dns_backup_file = str(backup)
        monkeypatch.setattr(gui.__class__, "_restore_dns_windows",
                            lambda self, snap: ["Ethernet"])
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        reverted = []
        monkeypatch.setattr(gui, "revert_system_dns", lambda: reverted.append(1))
        gui._revert_after_restore_attempt()
        assert reverted == [], "reset-to-DHCP must not fire while a retryable backup exists"
        assert backup.exists()

    def test_missing_backup_allows_last_resort_reset(self, gui, tmp_path, monkeypatch):
        gui.dns_backup_file = str(tmp_path / "absent.json")
        reverted = []
        monkeypatch.setattr(gui, "revert_system_dns", lambda: reverted.append(1))
        gui._revert_after_restore_attempt()
        assert reverted == [1]

    def test_wrong_platform_payload_is_ignored(self, gui, tmp_path, monkeypatch):
        backup = tmp_path / "dns_backup.json"
        self._write_backup(str(backup), platform_name="Darwin")
        gui.dns_backup_file = str(backup)
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        called = []
        monkeypatch.setattr(gui.__class__, "_restore_dns_linux",
                            lambda self, snap: called.append(1) or [])
        assert gui.restore_dns_backup() is False
        assert not called, "payload for another OS must never be applied"


class _FakeRoot:
    def geometry(self):
        return "1100x850+20+20"

    def state(self):
        return "normal"

    def withdraw(self):
        pass  # messagebox may call this on the parent root; must not raise


def make_gui_with_root(tmp_path):
    """A gui whose persistence paths live in tmp and that has a fake root."""
    gui = make_gui()
    gui.root = _FakeRoot()
    gui.settings_file = os.path.join(str(tmp_path), "settings.json")
    gui.cache_file = os.path.join(str(tmp_path), "server_cache.json")
    gui.dns_backup_file = os.path.join(str(tmp_path), "dns_backup.json")
    return gui


class TestSettingsRoundTrip:
    def test_save_then_load_preserves_values(self, tmp_path):
        gui = make_gui_with_root(tmp_path)
        gui.block_ipv6_var.set(True)
        gui.require_nolog_var.set(True)
        gui.cache_size_var.set("1024")
        gui.protocol_filter_var.set("DoH")
        gui.config_dir_var.set("/tmp/cfg")
        gui.proxy_path_var.set("/usr/bin/dnscrypt-proxy")
        gui.server_relay_map = {"srv": ["relay"]}
        gui.save_settings()
        assert os.path.exists(gui.settings_file)

        other = make_gui_with_root(tmp_path)
        loaded = other.load_settings()
        assert loaded["block_ipv6"] is True
        assert loaded["require_nolog"] is True
        assert loaded["cache_size"] == "1024"
        assert loaded["ui_filter_protocol"] == "DoH"
        assert loaded["config_dir"] == "/tmp/cfg"
        assert loaded["proxy_executable_path"] == "/usr/bin/dnscrypt-proxy"
        assert loaded["server_relay_map"] == {"srv": ["relay"]}
        assert loaded["was_active"] is False

    def test_deactivation_persists_empty_state(self, tmp_path):
        gui = make_gui_with_root(tmp_path)
        gui.preferred_servers = ["old-server"]
        gui.save_settings()  # nothing active -> must record was_active=False
        loaded = make_gui_with_root(tmp_path).load_settings()
        assert loaded["was_active"] is False
        assert loaded["last_active_servers"] == []

    def test_corrupt_settings_fall_back_to_defaults(self, tmp_path):
        gui = make_gui_with_root(tmp_path)
        with open(gui.settings_file, "w") as fh:
            fh.write("{not json")
        defaults = gui.load_settings()
        assert defaults["block_ipv6"] is False
        assert defaults["cache_size"] == "512"


class TestEngineDiscovery:
    """The release ships a bundled engine but a system install is preferred
    whenever one is present, and an explicit user path always wins."""

    def _gui_with_bundled(self, tmp_path):
        exe_name = "dnscrypt-proxy" + (".exe" if os.name == "nt" else "")
        bundled = tmp_path / exe_name
        bundled.touch()
        # POSIX: the release archive ships with +x set by upstream packaging;
        # without it the discovery test cannot pass because `_is_runnable`
        # treats a 0o644 file as non-executable. Windows ignores the bit.
        if os.name != "nt":
            bundled.chmod(0o755)
        gui = make_gui()
        gui.base_path = str(tmp_path)
        return gui

    def test_explicit_path_wins_when_runnable(self, gui, tmp_path, monkeypatch):
        exe_name = "dnscrypt-proxy" + (".exe" if os.name == "nt" else "")
        explicit = tmp_path / "my" / exe_name
        explicit.parent.mkdir()
        explicit.touch()
        if os.name != "nt":
            explicit.chmod(0o755)
        gui.settings = {"proxy_executable_path": str(explicit)}
        _fake_which(monkeypatch, "/usr/bin/dnscrypt-proxy")
        path, source = gui._discover_engine()
        assert source == "explicit"
        assert path == str(explicit)

    def test_explicit_path_falls_through_when_not_runnable(self, gui, tmp_path, monkeypatch):
        """A broken explicit path (e.g. after a user moved files) must not
        pin the engine to 'missing' - it should fall through to whatever is
        actually usable, so the user is never permanently locked out."""
        explicit = tmp_path / "ghost" / "dnscrypt-proxy"
        gui.settings = {"proxy_executable_path": str(explicit)}
        _fake_which(monkeypatch, "/usr/bin/dnscrypt-proxy")
        path, source = gui._discover_engine()
        assert source == "system"
        assert path == "/usr/bin/dnscrypt-proxy"

    @pytest.mark.skipif(os.name == "nt", reason="POSIX execute bit is meaningless on Windows")
    def test_explicit_path_without_execute_bit_falls_through(self, gui, tmp_path, monkeypatch):
        exe_name = "dnscrypt-proxy" + (".exe" if os.name == "nt" else "")
        explicit = tmp_path / "my" / exe_name
        explicit.parent.mkdir()
        explicit.touch()
        if os.name != "nt":
            explicit.chmod(0o644)  # file exists but is NOT executable
        gui.settings = {"proxy_executable_path": str(explicit)}
        _fake_which(monkeypatch, "/usr/bin/dnscrypt-proxy")
        _path, source = gui._discover_engine()
        assert source == "system", (
            "non-executable explicit path must not block a working system install"
        )

    def test_system_path_used_when_no_explicit(self, gui, tmp_path, monkeypatch):
        _fake_which(monkeypatch, "/usr/bin/dnscrypt-proxy")
        gui.settings = {}
        path, source = gui._discover_engine()
        assert source == "system"
        assert path == "/usr/bin/dnscrypt-proxy"

    def test_bundled_used_when_no_system_install(self, gui, tmp_path, monkeypatch):
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        monkeypatch.delattr(sys, "_MEIPASS", raising=False)
        gui = self._gui_with_bundled(tmp_path)
        gui.settings = {}
        _fake_which(monkeypatch, None)
        exe_name = "dnscrypt-proxy" + (".exe" if os.name == "nt" else "")
        path, source = gui._discover_engine()
        assert source == "bundled"
        assert path == str(tmp_path / exe_name)

    def test_bundled_search_includes_frozen_meipass(self, gui, tmp_path, monkeypatch):
        exe_name = "dnscrypt-proxy" + (".exe" if os.name == "nt" else "")
        meipass = tmp_path / "_MEIPASS"
        meipass.mkdir()
        (meipass / exe_name).touch()
        if os.name != "nt":
            (meipass / exe_name).chmod(0o755)
        monkeypatch.setattr(sys, "frozen", True, raising=False)
        monkeypatch.setattr(sys, "_MEIPASS", str(meipass), raising=False)
        gui = make_gui()
        gui.base_path = str(tmp_path)
        gui.settings = {}
        _fake_which(monkeypatch, None)
        path, source = gui._discover_engine()
        assert source == "bundled"
        assert path == str(meipass / exe_name)
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        monkeypatch.delattr(sys, "_MEIPASS", raising=False)

    def test_missing_returns_missing_tag(self, gui, tmp_path, monkeypatch):
        _fake_which(monkeypatch, None)
        gui.settings = {}
        path, source = gui._discover_engine()
        assert source == "missing"
        assert path == ""


class TestIsRunnable:
    """`_is_runnable` is the single source of truth for 'can we launch this'.

    A test-suite-level guard so a future maintainer cannot silently weaken
    the executable check on POSIX (it has caused real launches to fail with
    PermissionError in the past)."""

    def test_empty_path_is_not_runnable(self, gui):
        assert gui._is_runnable("") is False

    def test_nonexistent_path_is_not_runnable(self, gui, tmp_path):
        assert gui._is_runnable(str(tmp_path / "nope")) is False

    def test_directory_is_not_runnable(self, gui, tmp_path):
        assert gui._is_runnable(str(tmp_path)) is False

    @pytest.mark.skipif(os.name == "nt", reason="POSIX execute bit is meaningless on Windows")
    def test_posix_non_executable_file_is_not_runnable(self, gui, tmp_path):
        f = tmp_path / "noexec"
        f.touch()
        f.chmod(0o644)
        assert gui._is_runnable(str(f)) is False

    @pytest.mark.skipif(os.name == "nt", reason="POSIX execute bit is meaningless on Windows")
    def test_posix_executable_file_is_runnable(self, gui, tmp_path):
        f = tmp_path / "exec"
        f.touch()
        f.chmod(0o755)
        assert gui._is_runnable(str(f)) is True


class TestCheckProxyExecutable:
    """End-to-end: the Configuration tab reflects what's actually in use."""

    def test_proxy_path_var_populated_from_discovery(self, gui, tmp_path, monkeypatch):
        exe_name = "dnscrypt-proxy" + (".exe" if os.name == "nt" else "")
        bundled = tmp_path / exe_name
        bundled.touch()
        if os.name != "nt":
            bundled.chmod(0o755)
        gui.base_path = str(tmp_path)
        gui.settings = {}
        _fake_which(monkeypatch, None)
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        monkeypatch.delattr(sys, "_MEIPASS", raising=False)

        import tkinter as tk
        gui.activate_button = _RecordingWidget()

        gui.check_proxy_executable()
        assert gui.proxy_executable == str(bundled)
        assert gui.proxy_path_var.get() == str(bundled)
        assert gui.activate_button.last_state == tk.NORMAL
        assert gui._version_probe_thread is not None
        assert isinstance(gui._version_probe_thread, threading.Thread)
        assert gui._version_probe_thread.daemon is True

    def test_missing_engine_disables_activate_button(self, gui, tmp_path, monkeypatch):
        import tkinter as tk
        gui.base_path = str(tmp_path)
        gui.settings = {}
        _fake_which(monkeypatch, None)
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        monkeypatch.delattr(sys, "_MEIPASS", raising=False)
        gui.activate_button = _RecordingWidget()
        gui.proxy_path_var = _RecordingVar("")
        gui.root = _FakeRoot()
        gui.messagebox_warnings = []

        def _warn(title, msg, **kwargs):
            gui.messagebox_warnings.append((title, msg))
        monkeypatch.setattr("dnscrypt_gui.messagebox.showwarning", _warn)

        gui.check_proxy_executable()
        assert gui.proxy_executable == ""
        assert gui.activate_button.last_state == tk.DISABLED
        assert gui.messagebox_warnings, "missing engine must surface a warning"
        assert "release archive" in gui.messagebox_warnings[0][1].lower()

    @pytest.mark.skipif(os.name == "nt", reason="POSIX execute bit is meaningless on Windows")
    def test_explicit_path_without_xbit_warns_with_configured_path(self, gui, tmp_path, monkeypatch):
        """When the user-configured path is non-executable on POSIX, the
        warning must point at THAT path - users can otherwise be confused
        why 'my install' wasn't picked up."""
        exe_name = "dnscrypt-proxy"
        explicit = tmp_path / "my" / exe_name
        explicit.parent.mkdir()
        explicit.touch()
        explicit.chmod(0o644)  # file exists, no execute bit
        gui.base_path = str(tmp_path)
        gui.settings = {"proxy_executable_path": str(explicit)}
        _fake_which(monkeypatch, None)
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        monkeypatch.delattr(sys, "_MEIPASS", raising=False)
        gui.activate_button = _RecordingWidget()
        gui.proxy_path_var = _RecordingVar(str(explicit))
        gui.root = _FakeRoot()
        gui.messagebox_warnings = []

        monkeypatch.setattr("dnscrypt_gui.messagebox.showwarning",
                            lambda *a, **k: gui.messagebox_warnings.append(a))

        import tkinter as tk
        gui.check_proxy_executable()
        assert gui.activate_button.last_state == tk.DISABLED
        assert gui.messagebox_warnings, "explicit non-executable must warn"
        msg = gui.messagebox_warnings[0][1]
        assert str(explicit) in msg
        assert "Configuration" in msg


class TestVersionProbeRegex:
    """The probe regex is the difference between "shows the engine version"
    and "shows the Go runtime version" on stderr. Test it directly so a
    future regex tweak cannot silently regress."""

    def test_matches_dnscrypt_version(self, gui):
        import re
        out = "dnscrypt-proxy 2.1.18"
        m = re.search(r"dnscrypt-proxy[^0-9]*v?(\d+\.\d+\.\d+)", out, re.IGNORECASE)
        assert m and m.group(1) == "2.1.18"

    def test_matches_with_v_prefix(self, gui):
        import re
        out = "dnscrypt-proxy v2.1.18"
        m = re.search(r"dnscrypt-proxy[^0-9]*v?(\d+\.\d+\.\d+)", out, re.IGNORECASE)
        assert m and m.group(1) == "2.1.18"

    def test_rejects_go_runtime_string(self, gui):
        """Go runtime version (e.g. "go1.21.0") must not be matched."""
        import re
        out = "go version go1.21.0"
        m = re.search(r"dnscrypt-proxy[^0-9]*v?(\d+\.\d+\.\d+)", out, re.IGNORECASE)
        assert m is None

    def test_rejects_bare_version(self, gui):
        import re
        out = "Some other program version 1.2.3"
        m = re.search(r"dnscrypt-proxy[^0-9]*v?(\d+\.\d+\.\d+)", out, re.IGNORECASE)
        assert m is None

    def test_dnscrypt_prefix_wins_over_go_runtime(self, gui):
        """When both appear on stderr, dnscrypt-proxy's own version must be
        captured, not Go's."""
        import re
        out = "dnscrypt-proxy 2.1.18 (built with go1.22.0)"
        m = re.search(r"dnscrypt-proxy[^0-9]*v?(\d+\.\d+\.\d+)", out, re.IGNORECASE)
        assert m and m.group(1) == "2.1.18"


class TestVersionProbe:
    def test_probe_returns_empty_for_nonexistent_path(self, gui):
        assert gui._probe_engine_version("/nonexistent/path") == ""

    def test_probe_returns_empty_for_empty_path(self, gui):
        assert gui._probe_engine_version("") == ""

    def test_version_probe_done_updates_label(self, gui):
        gui.proxy_executable = ""
        gui.engine_version = ""
        gui.engine_version_label = _RecordingLabel()
        gui._on_version_probe_done("")
        assert "(not found)" in gui.engine_version_label.last_text

    def test_version_probe_done_stores_version(self, gui):
        gui.proxy_executable = ""
        gui.engine_version = ""
        gui.engine_version_label = _RecordingLabel()
        gui._on_version_probe_done("")
        assert gui.engine_version == ""

    def test_stale_probe_result_is_dropped(self, gui):
        """If the user re-applies with a different engine, a late-arriving
        probe from the old binary must not overwrite the new label."""
        gui.proxy_executable = "/new/engine"
        gui.engine_version = ""
        gui.engine_version_label = _RecordingLabel()
        # The path the probe was scheduled for is the OLD one; callback
        # must detect the mismatch and refuse to touch the label.
        gui._on_version_probe_done("/old/engine")
        assert gui.engine_version == ""
        assert gui.engine_version_label.last_text is None

    def test_stale_probe_does_not_set_engine_version(self, gui):
        gui.proxy_executable = "/new/engine"
        gui.engine_version = "2.1.18"
        gui.engine_version_label = _RecordingLabel()
        gui._on_version_probe_done("/old/engine")
        # Untouched - the user's version is preserved until the new probe lands.
        assert gui.engine_version == "2.1.18"


class _RecordingWidget:
    def __init__(self):
        self.last_state = None

    def config(self, state=None, **_):
        if state is not None:
            self.last_state = state


class _RecordingVar:
    def __init__(self, value):
        self._value = value

    def get(self):
        return self._value

    def set(self, value):
        self._value = value


class _RecordingLabel:
    def __init__(self):
        self.last_text = None
        self.last_foreground = None
        self.last_cursor = None

    def config(self, **kwargs):
        if "text" in kwargs:
            self.last_text = kwargs["text"]
        if "foreground" in kwargs:
            self.last_foreground = kwargs["foreground"]
        if "cursor" in kwargs:
            self.last_cursor = kwargs["cursor"]


class _ReleaseResp:
    """Minimal stand-in for a requests.Response with status_code + headers + json."""

    def __init__(self, payload, status_code=200, etag=""):
        self._p = payload
        self.status_code = status_code
        self.headers = {"ETag": etag}

    def raise_for_status(self):
        pass

    def json(self):
        return self._p


# ----------------------------------------------------------------------
# Engine update check
# ----------------------------------------------------------------------

class TestEngineUpdateCheck:
    def test_fetch_latest_engine_release_returns_tag_and_url(self, gui, monkeypatch):
        import sys
        import types

        captured = {}

        def fake_get(url, **kwargs):
            captured["url"] = url
            return _ReleaseResp({"tag_name": "2.1.18", "html_url": "https://github.com/DNSCrypt/dnscrypt-proxy/releases/tag/2.1.18"})

        fake_requests = types.SimpleNamespace(get=fake_get)
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        tag, url = gui._fetch_latest_engine_release()
        assert tag == "2.1.18"
        assert url == "https://github.com/DNSCrypt/dnscrypt-proxy/releases/tag/2.1.18"
        assert "DNSCrypt/dnscrypt-proxy" in captured["url"]

    def test_fetch_latest_engine_release_handles_failure(self, gui, monkeypatch):
        import sys
        import types

        def boom(*a, **kw):
            raise OSError("network down")

        fake_requests = types.SimpleNamespace(get=boom)
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        assert gui._fetch_latest_engine_release() == (None, None)

    def test_fetch_latest_engine_release_normalises_url_to_string(self, gui, monkeypatch):
        import sys
        import types

        fake_requests = types.SimpleNamespace(
            get=lambda *a, **kw: _ReleaseResp({"tag_name": "2.1.18", "html_url": ["nonsense"]}))
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        tag, url = gui._fetch_latest_engine_release()
        assert tag == "2.1.18"
        assert url == "https://github.com/DNSCrypt/dnscrypt-proxy/releases/latest"

    def test_engine_update_available_sets_label(self, gui):
        gui.engine_version = "2.1.17"
        label = _RecordingLabel()
        gui.engine_version_label = label
        _orig = gui._post_ui
        gui._post_ui = lambda fn: fn()  # drain synchronously in tests
        try:
            gui._apply_engine_update_result("2.1.18", "https://github.com/DNSCrypt/dnscrypt-proxy/releases/tag/2.1.18")
        finally:
            gui._post_ui = _orig
        assert label.last_text is not None
        assert "2.1.17" in label.last_text
        assert "2.1.18" in label.last_text
        assert gui._engine_update_url == "https://github.com/DNSCrypt/dnscrypt-proxy/releases/tag/2.1.18"

    def test_engine_update_current_keeps_label_and_caches_url(self, gui):
        gui.engine_version = "2.1.18"
        label = _RecordingLabel()
        gui.engine_version_label = label
        gui._engine_update_url = "https://old-stale.invalid"
        _orig = gui._post_ui
        gui._post_ui = lambda fn: fn()
        try:
            gui._apply_engine_update_result("2.1.18", "https://example.com/release")
        finally:
            gui._post_ui = _orig
        # "current" branch updates the label with the current version and
        # refreshes the click-through URL so a stale URL never lingers.
        assert "2.1.18" in (label.last_text or "")
        assert gui._engine_update_url == "https://example.com/release"

    def test_engine_update_failure_preserves_previous_url(self, gui):
        """A failed check (None, None) must not overwrite a previously cached
        specific release URL with the generic releases page fallback."""
        gui.engine_version = "2.1.18"
        label = _RecordingLabel()
        gui.engine_version_label = label
        gui._engine_update_url = "https://github.com/DNSCrypt/dnscrypt-proxy/releases/tag/2.1.18"
        _orig = gui._post_ui
        gui._post_ui = lambda fn: fn()
        try:
            gui._apply_engine_update_result(None, None)
        finally:
            gui._post_ui = _orig
        # Label must not change on a failed check (working engine, no error).
        assert label.last_text is None
        # Previous specific URL must be preserved.
        assert gui._engine_update_url == "https://github.com/DNSCrypt/dnscrypt-proxy/releases/tag/2.1.18"

    def test_engine_update_inconclusive_does_not_overwrite_label(self, gui):
        gui.engine_version = "2.1.18"
        label = _RecordingLabel()
        gui.engine_version_label = label
        _orig = gui._post_ui
        gui._post_ui = lambda fn: fn()
        try:
            gui._apply_engine_update_result(None, None)
        finally:
            gui._post_ui = _orig
        assert label.last_text is None

    def test_engine_update_caches_tag_for_late_probe(self, gui):
        gui.engine_version = ""
        label = _RecordingLabel()
        gui.engine_version_label = label
        _orig = gui._post_ui
        gui._post_ui = lambda fn: fn()
        try:
            gui._apply_engine_update_result("2.1.18", "https://example/release")
        finally:
            gui._post_ui = _orig
        assert gui._engine_release_tag == "2.1.18"
        assert gui._engine_release_url == "https://example/release"
        gui.engine_version = "2.1.17"
        gui._apply_engine_update_result("2.1.18", "https://example/release")
        assert "2.1.17" in (label.last_text or "")
        assert "2.1.18" in (label.last_text or "")

    def test_update_check_worker_runs_both_checks(self, gui, monkeypatch):
        import sys
        import types

        class _Resp:
            def __init__(self, payload):
                self._p = payload
            status_code = 200
            headers = {"ETag": ""}  # noqa: RUF012

            def raise_for_status(self):
                pass

            def json(self):
                return self._p
        fake_requests = types.SimpleNamespace(
            get=lambda *a, **kw: _Resp({"tag_name": "v1.2.1", "html_url": "https://example/gui"}))
        monkeypatch.setitem(sys.modules, "requests", fake_requests)
        monkeypatch.delenv("DNSCRYPT_GUI_SKIP_UPDATE_CHECK", raising=False)
        called = {"gui": 0, "engine": 0}
        _orig = gui._post_ui
        gui._post_ui = lambda fn: fn()  # drain synchronously
        # Suppress the settings-file write that _save_release_settings would do;
        # this test only verifies that both checks are dispatched, not persistence.
        _orig_save = gui._save_release_settings
        gui._save_release_settings = lambda: None
        try:
            monkeypatch.setattr(gui, "_apply_update_result", lambda *a, **kw: called.__setitem__("gui", called["gui"] + 1))
            monkeypatch.setattr(gui, "_apply_engine_update_result",
                                lambda *a, **kw: called.__setitem__("engine", called["engine"] + 1))
            gui._update_check_worker(False)
        finally:
            gui._post_ui = _orig
        assert called == {"gui": 1, "engine": 1}

    def test_update_check_worker_reenables_button_on_skip(self, gui, monkeypatch):
        monkeypatch.setenv("DNSCRYPT_GUI_SKIP_UPDATE_CHECK", "1")
        _orig = gui._post_ui
        gui._post_ui = lambda fn: fn()
        try:
            gui._update_check_worker(True)
        finally:
            gui._post_ui = _orig
            monkeypatch.delenv("DNSCRYPT_GUI_SKIP_UPDATE_CHECK", raising=False)
        assert "skipped" in gui.status_var.get().lower()

    def test_open_engine_update_link_opens_url(self, gui, monkeypatch):
        gui._engine_update_url = "https://example.com/release"
        import webbrowser
        called = []
        monkeypatch.setattr(webbrowser, "open", lambda u: called.append(u) or True)
        gui._open_engine_update_link()
        assert called == ["https://example.com/release"]

    def test_open_engine_update_link_noop_when_no_url(self, gui, monkeypatch):
        gui._engine_update_url = None
        import webbrowser
        called = []
        monkeypatch.setattr(webbrowser, "open", lambda u: called.append(u) or True)
        gui._open_engine_update_link()
        assert called == []


class TestApplyUpdateResult:
    def test_gui_update_available_sets_status_and_url(self, gui):
        gui.update_status_label = _RecordingLabel()
        gui.gui_version_label = _RecordingLabel()
        _orig = gui._post_ui
        gui._post_ui = lambda fn: fn()
        try:
            gui._apply_update_result("v99.0.0", "https://example.com/gui")
        finally:
            gui._post_ui = _orig
        assert "99.0.0" in gui.update_status_label.last_text
        assert "available" in gui.update_status_label.last_text
        assert gui._update_url == "https://example.com/gui"

    def test_gui_update_current_clears_url(self, gui):
        from conftest import mod as _mod
        gui.update_status_label = _RecordingLabel()
        gui.gui_version_label = _RecordingLabel()
        gui._update_url = "https://example.com/stale"
        _orig = gui._post_ui
        gui._post_ui = lambda fn: fn()
        try:
            gui._apply_update_result(f"v{_mod.APP_VERSION}", "https://example.com/gui")
        finally:
            gui._post_ui = _orig
        assert gui._update_url is None

    def test_gui_update_inconclusive_sets_status_failed(self, gui):
        gui.update_status_label = _RecordingLabel()
        gui.gui_version_label = _RecordingLabel()
        _orig = gui._post_ui
        gui._post_ui = lambda fn: fn()
        try:
            # First set an "available" state to put the version label in link mode
            gui._apply_update_result("v99.0.0", "https://example.com/gui")
            # Now trigger the failure
            gui._apply_update_result(None, None)
        finally:
            gui._post_ui = _orig
        assert gui.update_status_label.last_text == "check failed"
        # Version label must also have its link styling cleared
        assert gui.gui_version_label.last_foreground == ""
        assert gui.gui_version_label.last_cursor == "arrow"

    def test_apply_update_result_handles_missing_label(self, gui):
        """The widget may not exist if the notebook tab was never created
        (e.g. in test harnesses); the applier must not crash."""
        _orig = gui._post_ui
        gui._post_ui = lambda fn: fn()
        try:
            gui._apply_update_result("v99.0.0", "https://example.com/gui")
        finally:
            gui._post_ui = _orig
        # No exception is the success criterion.

    def test_link_fg_returns_blue_when_style_empty(self, gui):
        """The make_gui fixture provides a style with empty lookup; the
        link color must be a sensible default in that case."""
        assert gui._link_fg() == "#0b7dda"

    def test_safe_url_rejects_non_string(self, gui):
        assert gui._safe_url(["list"], "https://fallback") == "https://fallback"
        assert gui._safe_url(None, "https://fallback") == "https://fallback"
        assert gui._safe_url("", "https://fallback") == "https://fallback"

    def test_safe_url_rejects_non_http_scheme(self, gui):
        assert gui._safe_url("javascript:alert(1)", "https://fallback") == "https://fallback"
        assert gui._safe_url("file:///etc/passwd", "https://fallback") == "https://fallback"

    def test_safe_url_accepts_http_and_https(self, gui):
        assert gui._safe_url("https://example.com/x", "fallback") == "https://example.com/x"
        assert gui._safe_url("http://example.com/x", "fallback") == "http://example.com/x"

    def test_apply_cached_release_hints_applies_gui_hint(self, gui, monkeypatch):
        gui._gui_cached_release_tag = "v99.0.0"
        gui._gui_cached_release_url = "https://example.com/gui"
        called = []

        def fake_apply(*args, **kwargs):
            called.append(args)

        monkeypatch.setattr(gui, "_apply_update_result", fake_apply)
        monkeypatch.setattr(gui, "_apply_engine_update_result", lambda *a, **k: None)
        gui._apply_cached_release_hints()
        assert called == [("v99.0.0", "https://example.com/gui")]

    def test_apply_cached_release_hints_applies_engine_hint(self, gui, monkeypatch):
        gui._engine_cached_release_tag = "2.1.99"
        gui._engine_cached_release_url = "https://example.com/engine"
        called = []

        def fake_engine(*args, **kwargs):
            called.append(args)

        monkeypatch.setattr(gui, "_apply_update_result", lambda *a, **k: None)
        monkeypatch.setattr(gui, "_apply_engine_update_result", fake_engine)
        gui._apply_cached_release_hints()
        assert called == [("2.1.99", "https://example.com/engine")]

    def test_apply_cached_release_hints_skips_empty_cache(self, gui, monkeypatch):
        called = []

        def noop(*a, **k):
            called.append(1)

        monkeypatch.setattr(gui, "_apply_update_result", noop)
        monkeypatch.setattr(gui, "_apply_engine_update_result", noop)
        gui._gui_cached_release_tag = ""
        gui._engine_cached_release_tag = ""
        gui._apply_cached_release_hints()
        assert called == []

    def test_save_release_settings_updates_settings_dict(self, gui, tmp_path, monkeypatch):
        gui.settings_file = str(tmp_path / "settings.json")
        gui.is_exiting = False
        gui.is_initialized = True
        gui._gui_release_etag = '"abc"'
        gui._gui_cached_release_tag = "v1.2.1"
        gui._gui_cached_release_url = "https://example.com/gui"
        gui._update_url = "https://example.com/release"
        gui._engine_release_etag = '"xyz"'
        gui._engine_cached_release_tag = "2.1.18"
        gui._engine_cached_release_url = "https://example.com/engine"
        gui._engine_update_url = "https://example.com/engine-release"
        gui.settings = {}  # empty dict to start
        gui._save_release_settings()
        assert gui.settings["gui_release_etag"] == '"abc"'
        assert gui.settings["gui_cached_release_tag"] == "v1.2.1"
        assert gui.settings["engine_release_etag"] == '"xyz"'
        assert gui.settings["engine_cached_release_tag"] == "2.1.18"

    def test_save_release_settings_preserves_existing_cached_values_on_empty_instance_attrs(self, gui, tmp_path, monkeypatch):
        gui.settings_file = str(tmp_path / "settings.json")
        gui.is_exiting = False
        gui.is_initialized = True
        # Simulate a transient network failure: instance attributes are None/empty
        gui._gui_release_etag = None
        gui._gui_cached_release_tag = None
        gui._gui_cached_release_url = None
        gui._update_url = None
        gui._engine_release_etag = ""
        gui._engine_cached_release_tag = ""
        gui._engine_cached_release_url = ""
        gui._engine_update_url = ""
        # Previous successful cache exists in settings
        gui.settings = {
            "gui_cached_release_tag": "v1.2.0",
            "gui_cached_release_url": "https://example.com/old-gui",
            "gui_release_etag": '"old-etag"',
        }
        gui._save_release_settings()
        # None/empty instance attrs must NOT overwrite existing cached values
        assert gui.settings.get("gui_cached_release_tag") == "v1.2.0"
        assert gui.settings.get("gui_cached_release_url") == "https://example.com/old-gui"

    def test_save_release_settings_skips_when_not_initialized(self, gui, tmp_path, monkeypatch):
        gui.settings_file = str(tmp_path / "settings.json")
        gui.is_exiting = False
        gui.is_initialized = False
        gui._save_release_settings()
        import os
        assert not os.path.exists(gui.settings_file)
