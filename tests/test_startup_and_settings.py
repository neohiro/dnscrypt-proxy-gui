"""Tests for autostart registration helpers, DNS backup policy and settings."""
import json
import os
import platform
import sys

from conftest import make_gui


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
