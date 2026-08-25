"""Full restart-cycle integration test.

Boots the real GUI against a stub proxy process (an interpreter that
sleeps), with every system-DNS operation stubbed, then drives the exact
code paths the buttons use:

    activate -> update_config_and_restart_proxy -> deactivate

and asserts that the proxy process is really replaced (new PID) and
finally really stopped. This is the regression net for deferred-state
bugs in the activation flow (see 'Instant Apply' fix).

Runs under xvfb in CI and on any desktop session locally.
"""
import os
import sys
import threading
import time


import pytest

from conftest import mod

pytestmark = pytest.mark.integration


def wait_until(predicate, timeout=45.0, interval=0.05, pump=None):
    """Poll predicate, pumping the Tk event loop so queued UI closures
    (status updates, state resets) actually execute without a mainloop."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pump is not None:
            try:
                pump()
            except Exception:
                pass
        if predicate():
            return True
        time.sleep(interval)
    return False


@pytest.fixture(scope="module")
def stub_proxy(tmp_path_factory):
    path = tmp_path_factory.mktemp("stub") / "stub_proxy.py"
    path.write_text("import time\n\nwhile True:\n    time.sleep(3600)\n")
    return str(path)


@pytest.fixture
def gui(stub_proxy, monkeypatch, tmp_path):
    # Hermetic runtime state: wipe settings.json next to the repo root if a
    # previous run left one behind.
    settings = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "settings.json")
    if os.path.exists(settings):
        os.remove(settings)

    FAKE_EXE = "dnscrypt-proxy-stub"

    def _fake_check(self):
        self.proxy_executable = FAKE_EXE

    cls = mod.DNSCryptClientGUI
    # monkeypatch.setattr so EVERY stub is undone after the test - direct
    # class assignments here leaked into unrelated later tests.
    monkeypatch.setattr(cls, "set_system_dns", lambda self, dns: True)
    monkeypatch.setattr(cls, "revert_system_dns", lambda self: True)
    monkeypatch.setattr(cls, "create_dns_backup", lambda self: None)
    monkeypatch.setattr(cls, "restore_dns_backup", lambda self: True)
    monkeypatch.setattr(cls, "check_startup_status", lambda self: None)
    monkeypatch.setattr(cls, "check_proxy_executable", _fake_check)

    def _print_dialog(title):
        def show(*args, **kwargs):
            print(f"[dialog:{title}] {' | '.join(str(a) for a in args)}",
                  flush=True)
        return show

    for name in ("showerror", "showwarning", "showinfo", "askyesno"):
        monkeypatch.setattr(mod.messagebox, name, _print_dialog(name))

    original_popen = mod.subprocess.Popen

    def intercepting_popen(cmd, *args, **kwargs):
        if cmd and cmd[0] == FAKE_EXE:
            cmd = [sys.executable, stub_proxy]
        return original_popen(cmd, *args, **kwargs)

    monkeypatch.setattr(mod.subprocess, "Popen", intercepting_popen)

    import tkinter as tk
    root = tk.Tk()
    instance = mod.DNSCryptClientGUI(root)
    # Linux default config dir is /etc/dnscrypt-proxy (root-owned); point
    # the test at a writable location like a configured install would.
    instance.config_dir_var.set(str(tmp_path))
    yield instance
    proc = getattr(instance, "proxy_process", None)
    if proc is not None and proc.poll() is None:
        proc.kill()
        proc.wait(timeout=5)
    try:
        root.destroy()
    except Exception:
        pass


class TestRestartCycle:
    def test_activate_change_deactivate_replaces_process(self, gui):
        print("[step] lock-wait", flush=True)
        gui._posted_names = []
        _orig_post = gui._post_ui

        def logging_post(fn):
            name = getattr(fn, "__name__", repr(fn))
            gui._posted_names.append(name)

            def runner(fn=fn, name=name):
                print(f"[ui-run {name}] start", flush=True)
                try:
                    fn()
                except Exception:
                    import traceback
                    print(f"[ui-run {name}] FAILED", flush=True)
                    traceback.print_exc(file=sys.stdout)
                    sys.stdout.flush()
                    raise
                print(f"[ui-run {name}] ok", flush=True)

            _orig_post(runner)

        gui._post_ui = logging_post
        drain_stats = {"runs": 0}
        _orig_drain = gui._drain_ui_queue

        def logged_drain():
            drain_stats["runs"] += 1
            _orig_drain()

        gui._drain_ui_queue = logged_drain
        pump = lambda: (gui.root.update(), loud_drain())

        _orig_worker = gui._activation_worker

        def _traced_worker(server_list):
            print("[worker] enter", flush=True)
            try:
                _orig_worker(server_list)
                print("[worker] exit ok", flush=True)
            except Exception:
                import traceback
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
                raise

        gui._activation_worker = _traced_worker

        def loud_drain():
            """Drain that REPORTS the first failing closure instead of
            silently starving the queue behind it."""
            import queue as _q
            while True:
                try:
                    fn = gui._ui_queue.get_nowait()
                except _q.Empty:
                    return
                try:
                    fn()
                except Exception:
                    import traceback
                    print("[drain-closure FAILED]", flush=True)
                    traceback.print_exc(file=sys.stdout)
                    sys.stdout.flush()

        servers = [{"name": "cycle-a", "stamp": "sdns://AQcAAAAAAAAAAQ",
                    "proto_type": "DNSCrypt", "no-log": "\u2713",
                    "dnssec": "\u2713", "no-filter": "\u2713",
                    "description": ""}]

        try:
            # --- Phase 0: let startup work (list fetch) release its lock ---
            def lock_is_free():
                acquired = gui.action_lock.acquire(blocking=False)
                if acquired:
                    gui.action_lock.release()
                return acquired

            assert wait_until(lock_is_free, pump=pump), \
                "startup operations never released the action lock"

            print("[step] phase1 start", flush=True)
            # --- Phase 1: activate through the button's worker ---
            worker = threading.Thread(
                target=gui._activation_worker, args=(servers,), daemon=True)
            worker.start()
            assert wait_until(lambda: bool(gui.active_server_info),
                              pump=pump), "activation never completed"
            assert wait_until(lambda: gui.proxy_process.poll() is None,
                              pump=pump), "proxy died immediately"
            pid1 = gui.proxy_process.pid
            worker.join(timeout=10)

            print("[step] phase2 start", flush=True)
            # --- Phase 2: config change must replace the running proxy ---
            gui.cache_size_var.set("2048")
            gui.update_config_and_restart_proxy()

            def replacement_spawned():
                proc = gui.proxy_process
                return proc is not None and proc.pid != pid1

            assert wait_until(replacement_spawned, pump=pump), \
                "config change did not spawn a replacement proxy"
            pid2 = gui.proxy_process.pid
            assert wait_until(lambda: bool(gui.active_server_info),
                              pump=pump), "state was not restored after restart"
            assert gui.proxy_process.poll() is None
            assert pid1 != pid2

            print("[step] phase3 start", flush=True)
            # --- Phase 3: deactivate really stops the replacement ---
            stopper = threading.Thread(
                target=gui._activation_worker, args=(None,), daemon=True)
            stopper.start()
            stopped = wait_until(
                lambda: (gui.proxy_process is None
                         or gui.proxy_process.poll() is not None),
                pump=pump)
            assert stopped, "deactivate did not stop the proxy"
            stopper.join(timeout=10)
            assert wait_until(lambda: gui.active_server_info == [], pump=pump)
        finally:
            print("[stats] posted:", gui._posted_names,
                  "drain_runs:", drain_stats["runs"], flush=True)
