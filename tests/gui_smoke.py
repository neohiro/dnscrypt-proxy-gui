"""End-to-end GUI smoke test.

Boots the real Tkinter application with all DNS-touching operations and the
proxy-executable check stubbed out, then exercises tree population,
selection, filtering, config generation and the tray->UI queue.

Runs anywhere tkinter works; in CI it is executed under xvfb-run.
Deliberately NOT named *_test.py so pytest never collects it - the module
boots a GUI at run time and must only execute as a script.
Exit code 0 = all checks passed.
"""
import importlib.util
import os
import sys
from importlib.machinery import SourceFileLoader


def main():
    REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    MODULE_PATH = os.path.join(REPO, "dnscrypt-proxy-gui.PY")

    loader = SourceFileLoader("dnscrypt_gui", MODULE_PATH)
    spec = importlib.util.spec_from_loader("dnscrypt_gui", loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dnscrypt_gui"] = mod
    loader.exec_module(mod)

    # --- Safety stubs: never touch real DNS or system state ---
    mod.DNSCryptClientGUI.set_system_dns = lambda self, dns: True
    mod.DNSCryptClientGUI.revert_system_dns = lambda self: True
    mod.DNSCryptClientGUI.create_dns_backup = lambda self: None
    mod.DNSCryptClientGUI.restore_dns_backup = lambda self: True
    mod.DNSCryptClientGUI.check_startup_status = lambda self: None

    def _fake_check_proxy(self):
        self.proxy_executable = "dnscrypt-proxy.exe"  # attribute must exist

    mod.DNSCryptClientGUI.check_proxy_executable = _fake_check_proxy

    SAMPLE = [
        {"name": "smoke-a", "stamp": "sdns://AQcAAAAAAAAABzEuMi4zLjQ", "proto_type": "DNSCrypt",
         "no-log": "\u2713", "dnssec": "\u2713", "no-filter": "\u2713", "description": "A"},
        {"name": "smoke-b", "stamp": "sdns://AgcAAAAAAAAABzEuMC4wLjGgAAEBAAABAQE", "proto_type": "DoH",
         "no-log": "\u2717", "dnssec": "\u2713", "no-filter": "\u2717", "description": "B"},
    ]

    def fake_fetch(self):
        self.server_data = SAMPLE
        self.relay_data = [{"name": "relay-x", "stamp": "sdns://AQRRRUxBWSAAAAA="}]
        self.root.after(0, self.on_fetch_complete)

    mod.DNSCryptClientGUI._fetch_and_parse_servers = fake_fetch

    import tomllib
    import tkinter as tk

    # Hermetic start: wipe runtime state a previous run may have left next to
    # the script (the app legitimately persists UI choices like the filter).
    for _junk in ("settings.json",):
        _p = os.path.join(REPO, _junk)
        if os.path.exists(_p):
            os.remove(_p)

    root = tk.Tk()
    gui = mod.DNSCryptClientGUI(root)

    results = []
    CHECKS = ["select+details", "config-gen", "filter", "queue-drain"]

    def step1():
        # Wait until the fake fetch has populated the tree (timing-safe).
        if not gui.tree.get_children(""):
            root.after(100, step1)
            return
        gui.proto_combo.set("All Protocols")
        gui.on_filter_changed()
        gui.tree.selection_set(["smoke-a"])
        gui.on_server_select(None)
        results.append(("select+details", bool(gui.details_text.get("1.0", "end").strip())))
        content = gui._generate_config_content(SAMPLE)
        parsed = tomllib.loads(content)
        results.append(("config-gen", parsed["server_names"] == ["smokea", "smokeb"]))
        gui.proto_combo.set("DoH")
        gui.on_filter_changed()
        kids = len(gui.tree.get_children(""))
        results.append(("filter", kids == 1))
        gui._post_ui(lambda: results.append(("queue-drain", True)))
        root.after(400, finish)

    def finish():
        try:
            root.destroy()
        except Exception:
            pass

    root.after(600, step1)          # let init/fetch settle first
    root.after(8000, finish)        # hard stop
    root.mainloop()

    ok = len(results) == len(CHECKS)
    for name, passed in results:
        print(f"{'PASS' if passed else 'FAIL'} {name}")
        ok = ok and passed
    if len(results) != len(CHECKS):
        print(f"INCOMPLETE: only {len(results)}/{len(CHECKS)} checks ran")
    print("SMOKE TEST:", "OK" if ok else "FAILED")
    sys.stdout.flush()
    os._exit(0 if ok else 1)  # hard exit: no stray native modal loop can hang us


if __name__ == "__main__":
    main()
