"""Test scaffolding for dnscrypt-proxy-gui.

Safety rules:
- The GUI class is instantiated via ``object.__new__`` so that ``__init__``
  never runs: no Tk mainloop, no background threads, no system DNS changes.
- tkinter variables are replaced by lightweight fakes.
"""
import importlib.util
import os
import sys
from importlib.machinery import SourceFileLoader

import pytest

# Tests must never phone home for updates.
os.environ.setdefault("DNSCRYPT_GUI_SKIP_UPDATE_CHECK", "1")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_PATH = os.path.join(REPO_ROOT, "dnscrypt-proxy-gui.PY")


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "integration: boots the real GUI and a stub proxy process")


def _load_module():
    # The upstream filename uses an uppercase .PY suffix, which importlib does
    # not treat as source by default - load it explicitly.
    loader = SourceFileLoader("dnscrypt_gui", MODULE_PATH)
    spec = importlib.util.spec_from_loader("dnscrypt_gui", loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("dnscrypt_gui", mod)
    loader.exec_module(mod)
    return mod


mod = _load_module()
DNSCryptClientGUI = mod.DNSCryptClientGUI


class FakeVar:
    """Minimal stand-in for tkinter variable objects."""

    def __init__(self, value):
        self._value = value

    def get(self):
        return self._value

    def set(self, value):
        self._value = value


class _RecordingButton:
    """Minimal stand-in for ttk.Button used by the test suite.

    Records the most recent `state=` argument passed to `config()` so tests
    can assert on button enable/disable transitions. Keyword arguments
    other than `state` and `text` are silently ignored - matches the subset
    of ttk.Button.config() used by the production code.
    """

    def __init__(self):
        self.last_state = None
        self.last_text = None
        self.config_calls = []

    def config(self, state=None, text=None, **_):
        if state is not None:
            self.last_state = state
        if text is not None:
            self.last_text = text
        self.config_calls.append((state, text))


def make_gui():
    """Build a bare GUI instance with pure-function dependencies injected."""
    gui = object.__new__(DNSCryptClientGUI)
    gui.server_data = []
    gui.relay_data = []
    gui.server_relay_map = {}
    gui.active_server_info = []
    gui.preferred_servers = []
    gui.is_exiting = False
    gui.is_initialized = True
    gui.base_path = REPO_ROOT
    gui.sort_stack = []
    gui.sort_dirs = {}
    gui.settings = {}
    gui.tray_broken = False
    gui._auto_activation_started = False
    import queue
    gui._ui_queue = queue.Queue()

    gui.block_ipv6_var = FakeVar(False)
    gui.require_dnssec_var = FakeVar(False)
    gui.require_nolog_var = FakeVar(False)
    gui.require_nofilter_var = FakeVar(False)
    gui.cache_size_var = FakeVar("512")
    gui.cache_neg_ttl_var = FakeVar("60")
    gui.cache_min_ttl_var = FakeVar("60")
    gui.protocol_filter_var = FakeVar("All Protocols")
    gui.start_minimized_var = FakeVar(False)
    gui.startup_var = FakeVar(False)
    gui.proxy_path_var = FakeVar("")
    gui.config_dir_var = FakeVar("")
    gui.engine_version = ""
    gui._version_probe_thread = None
    gui._engine_update_url = None
    gui._engine_release_tag = ""
    gui._engine_release_url = ""
    gui._gui_release_etag = ""
    gui._gui_cached_release_tag = ""
    gui._gui_cached_release_url = ""
    gui._engine_release_etag = ""
    gui.status_var = FakeVar("")
    gui.style = type("S", (), {"lookup": staticmethod(lambda *a, **k: "")})()
    gui.activate_button = _RecordingButton()
    gui.restart_button = _RecordingButton()
    return gui


@pytest.fixture
def gui():
    return make_gui()


@pytest.fixture
def sample_servers():
    return [
        {
            "name": "example-a",
            "stamp": "sdns://AQcAAAAAAAAADzE5Mi4xNjguMS4xIOAAAQ",
            "proto_type": "DNSCrypt",
            "no-log": "✓",
            "dnssec": "✓",
            "no-filter": "✓",
            "description": "Test server A",
        },
        {
            "name": "example-b.doh",
            "stamp": "sdns://AgcAAAAAAAAABzEuMC4wLjGgAAEBAAABAQE",
            "proto_type": "DoH",
            "no-log": "✗",
            "dnssec": "✓",
            "no-filter": "✗",
            "description": "Test DoH server B",
        },
        {
            "name": "collision.a",
            "stamp": "sdns://AQcAAAAAAAAADzE5Mi4xNjguMS4zIOAAAw",
            "proto_type": "DNSCrypt",
            "no-log": "✓",
            "dnssec": "✗",
            "no-filter": "✓",
            "description": "Name collides after sanitisation",
        },
    ]
