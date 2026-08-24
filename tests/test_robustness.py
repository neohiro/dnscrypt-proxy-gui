"""Robustness regression tests: name dedupe and auto-activation guard."""
import json
import os
import types

from conftest import FakeVar, make_gui, mod


class TestDedupeByName:
    def test_duplicates_keep_first_occurrence(self, gui):
        items = [{"name": "a", "stamp": "1"}, {"name": "a", "stamp": "2"}]
        out = gui._dedupe_by_name(items)
        assert [i["stamp"] for i in out] == ["1"]

    def test_missing_or_empty_names_dropped(self, gui):
        items = [{"stamp": "x"}, {"name": "", "stamp": "y"},
                 {"name": "ok", "stamp": "z"}]
        assert [i["name"] for i in gui._dedupe_by_name(items)] == ["ok"]

    def test_non_dict_entries_dropped(self, gui):
        assert gui._dedupe_by_name(["junk", 42, {"name": "ok"}]) == [{"name": "ok"}]

    def test_unique_input_unchanged(self, gui):
        items = [{"name": "a"}, {"name": "b"}]
        assert gui._dedupe_by_name(items) == items

    def test_cache_load_dedupes(self, tmp_path):
        gui = make_gui()
        gui.cache_file = os.path.join(str(tmp_path), "server_cache.json")
        payload = {
            "servers": [{"name": "dup", "stamp": "first"},
                        {"name": "dup", "stamp": "second"}],
            "relays": [],
            "timestamp": 123.0,
        }
        with open(gui.cache_file, "w") as fh:
            json.dump(payload, fh)
        gui.load_server_cache()
        assert len(gui.server_data) == 1
        assert gui.server_data[0]["stamp"] == "first"
        assert set(gui._server_by_name) == {"dup"}


class TestAutoActivationGuard:
    def _wired_gui(self, monkeypatch, rows=("a", "b")):
        gui = make_gui()
        gui.status_var = FakeVar("")
        gui.tree = types.SimpleNamespace(
            get_children=lambda *a: list(rows),
            selection_set=lambda ids: None,
        )
        gui.server_data = [
            {"name": "a", "stamp": "sdns://AQ", "proto_type": "DNSCrypt",
             "no-log": "\u2713", "dnssec": "\u2713", "no-filter": "\u2713",
             "description": ""},
            {"name": "b", "stamp": "sdns://AQ", "proto_type": "DNSCrypt",
             "no-log": "\u2713", "dnssec": "\u2713", "no-filter": "\u2713",
             "description": ""},
        ]
        gui._server_by_name = {s["name"]: s for s in gui.server_data}
        spawned = []

        class FakeThread:
            def __init__(self, target=None, daemon=None, **kwargs):
                spawned.append(target)

            def start(self):
                pass

        monkeypatch.setattr(mod.threading, "Thread", FakeThread)
        return gui, spawned

    def test_second_invocation_does_not_respawn(self, monkeypatch):
        gui, spawned = self._wired_gui(monkeypatch)
        gui.preferred_servers = ["a"]
        gui.check_auto_activation()
        gui.check_auto_activation()  # e.g. fetch completes after cache load
        assert len(spawned) == 1

    def test_no_match_does_not_block_later_success(self, monkeypatch):
        gui, spawned = self._wired_gui(monkeypatch)
        gui.preferred_servers = ["missing-server"]
        gui.check_auto_activation()
        gui.server_data.append({"name": "missing-server", "stamp": "sdns://AQ"})
        gui._server_by_name["missing-server"] = gui.server_data[-1]
        gui.check_auto_activation()
        assert len(spawned) == 1

    def test_no_preferences_is_noop(self, monkeypatch):
        gui, spawned = self._wired_gui(monkeypatch)
        gui.preferred_servers = []
        gui.check_auto_activation()
        assert spawned == []

class TestDeactivateStateContract:
    """update_config_and_restart_proxy checks active_server_info right
    after deactivate_dns returns on a worker thread; the clear must
    therefore happen synchronously, not in the queued UI reset."""

    class _InlineRoot:
        def after(self, ms, fn=None):
            if fn:
                fn()

    @staticmethod
    def _widget():
        return types.SimpleNamespace(config=lambda **k: None)

    def test_state_clears_before_queued_ui_reset(self, gui, monkeypatch):
        gui.root = self._InlineRoot()
        gui.activate_button = self._widget()
        gui.status_indicator = self._widget()
        gui.active_server_label = self._widget()
        gui.status_var = FakeVar("")
        gui.tree = types.SimpleNamespace(selection=lambda: [])
        gui.proxy_process = None
        gui.dns_backup_file = os.path.join("does", "not", "exist.json")
        gui.save_settings = lambda: None
        gui.active_server_info = [{"name": "a"}]
        monkeypatch.setattr(gui.__class__, "_revert_after_restore_attempt",
                            lambda self: None)
        gui.deactivate_dns()
        assert gui.active_server_info == [], (
            "restart flow must observe the cleared state immediately")

    def test_restart_flow_would_reactivate(self, gui, monkeypatch):
        """Replicates the update_config_and_restart_proxy decision."""
        gui.root = self._InlineRoot()
        gui.activate_button = self._widget()
        gui.status_indicator = self._widget()
        gui.active_server_label = self._widget()
        gui.status_var = FakeVar("")
        gui.tree = types.SimpleNamespace(selection=lambda: [])
        gui.proxy_process = None
        gui.dns_backup_file = os.path.join("does", "not", "exist.json")
        gui.save_settings = lambda: None
        gui.active_server_info = [{"name": "a"}]
        monkeypatch.setattr(gui.__class__, "_revert_after_restore_attempt",
                            lambda self: None)
        reactivated = []
        monkeypatch.setattr(gui, "activate_dns",
                            lambda servers: reactivated.append(servers))
        current_servers = gui.active_server_info
        gui.deactivate_dns()
        if not gui.active_server_info:
            gui.activate_dns(current_servers)
        assert reactivated == [current_servers]
