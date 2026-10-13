#!/usr/bin/env python3
"""DNSCrypt Proxy GUI - cross-platform controller for dnscrypt-proxy."""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
# import requests # Moved to local scope for faster startup
import threading
import collections
import queue
import os
import sys
import subprocess
import shutil
import platform
import atexit
import time
import json
import re
import base64
import logging
import tempfile
from logging.handlers import RotatingFileHandler

# --- New Imports for Tray Icon and Startup ---
try:
    from pystray import MenuItem as item, Icon as icon
    from PIL import Image
    TRAY_AVAILABLE = True
except Exception:
    # pystray's X11 backend opens the display at import time and can raise
    # non-ImportError errors on headless or Wayland-only systems; falling
    # back to the no-tray path must never crash the app itself.
    TRAY_AVAILABLE = False

if platform.system() == "Windows":
    import winreg

# --- Constants ---
APP_NAME = "DNSCryptClientGUI"
APP_VERSION = "1.3.0"

# dnscrypt-proxy cache tunables. Note: cache_size counts ENTRIES, not bytes.
CACHE_SIZE_DEFAULT, CACHE_SIZE_MIN, CACHE_SIZE_MAX = 512, 64, 1 << 20
CACHE_TTL_DEFAULT, CACHE_TTL_MIN, CACHE_TTL_MAX = 60, 0, 7 * 24 * 3600

# Update-check endpoints.
#   GUI release: neohiro/dnscrypt-proxy-gui (this project).
#   Engine release: DNSCrypt/dnscrypt-proxy (bundled engine source).
# Both return GitHub's standard release JSON ("tag_name", "html_url", "name");
# unauthenticated calls are rate-limited to 60 req/hr per IP.
LATEST_RELEASE_API = "https://api.github.com/repos/neohiro/dnscrypt-proxy-gui/releases/latest"
LATEST_ENGINE_RELEASE_API = "https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest"
RELEASES_PAGE = "https://github.com/neohiro/dnscrypt-proxy-gui/releases/latest"
ENGINE_RELEASES_PAGE = "https://github.com/DNSCrypt/dnscrypt-proxy/releases/latest"
RESOLVERS_URL = "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md"
RELAYS_URL = "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md"
CONFIG_FILE = "dnscrypt-proxy.toml"
SETTINGS_FILE_NAME = "settings.json"
CACHE_FILE_NAME = "server_cache.json" 
DNS_BACKUP_FILE_NAME = "dns_backup.json"
ICON_FILE = "icon.ico"

# --- Console Suppression Helper ---
if sys.platform == "win32" and getattr(sys, 'frozen', False):
    class NullWriter:
        def write(self, data): pass
        def flush(self): pass
    sys.stdout = NullWriter()
    sys.stderr = NullWriter()

def is_admin():
    """Check if the process is running with admin/root privileges.

    The result is cached after the first *successful* call. Admin status does
    not change for the lifetime of a process (privilege can only be gained via
    a new process, e.g. ShellExecuteW with runas), so repeated calls from
    _run_hidden, the activation path, and the startup elevation check would
    otherwise pay the cost of ctypes + Windows syscall on every call.
    A transient OSError during the check is NOT cached, so the next call
    gets a fresh attempt rather than permanently caching a failure."""
    cached = getattr(is_admin, "_cached_result", None)
    if cached is not None:
        return cached
    try:
        if platform.system() == "Windows":
            import ctypes
            result = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            result = os.geteuid() == 0
    except Exception:
        LOG.debug("Admin check failed", exc_info=True)
        return False
    is_admin._cached_result = result
    return result

# --- Logging ---
# A rotating file log is essential for a GUI that suppresses stdout when
# frozen: without it, activation failures and DNS errors are invisible.
def _log_directory():
    system = platform.system()
    if system == "Windows":
        root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(root, APP_NAME, "logs")
    if system == "Darwin":
        return os.path.expanduser("~/Library/Logs/" + APP_NAME)
    cache = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(cache, APP_NAME.lower(), "logs")


def setup_logging():
    logger = logging.getLogger(APP_NAME)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
    for target in (_log_directory(), os.path.join(tempfile.gettempdir(), APP_NAME)):
        try:
            os.makedirs(target, exist_ok=True)
            handler = RotatingFileHandler(
                os.path.join(target, "dnscrypt-proxy-gui.log"),
                maxBytes=512 * 1024,
                backupCount=2,
                encoding="utf-8",
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            break
        except OSError:
            continue
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    logger.addHandler(console)  # swallowed harmlessly in frozen builds
    return logger


LOG = setup_logging()


def _writable_dir(candidate):
    try:
        os.makedirs(candidate, exist_ok=True)
        probe = os.path.join(candidate, ".write_probe")
        with open(probe, "w"):
            pass
        os.remove(probe)
        return True
    except OSError:
        return False


def _default_data_directory(base_path):
    """Settings/cache live next to the executable when possible (portable
    mode); otherwise fall back to the per-OS application data directory so
    installs under Program Files / /usr still work."""
    if _writable_dir(base_path):
        return base_path
    system = platform.system()
    if system == "Windows":
        root = os.environ.get("APPDATA") or os.path.expanduser("~")
        data_dir = os.path.join(root, APP_NAME)
    elif system == "Darwin":
        data_dir = os.path.expanduser("~/Library/Application Support/" + APP_NAME)
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        data_dir = os.path.join(xdg, APP_NAME.lower())
    try:
        os.makedirs(data_dir, exist_ok=True)
    except OSError:
        return base_path  # last resort; individual writes will log failures
    return data_dir


def acquire_single_instance_lock():
    """Best-effort single-instance enforcement.

    Windows uses a named mutex; POSIX an flock'd lock file that the kernel
    releases automatically on process death. Returns a keep-alive token, or
    None when another instance is already running."""
    system = platform.system()
    if system == "Windows":
        import ctypes
        # GetLastError must be captured through ctypes' own machinery: a
        # plain windll call can be preceded by other ctypes invocations
        # that clobber the thread's last-error value.
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ERROR_ALREADY_EXISTS = 183
        mutex = kernel32.CreateMutexW(None, False, "Global\\" + APP_NAME)
        if mutex and ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
            return None
        return ("mutex", mutex)
    lock_path = os.path.join(tempfile.gettempdir(), f"{APP_NAME}.instance.lock")
    handle = open(lock_path, "w")
    try:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    return ("file", handle)

class DNSCryptClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DNSCrypt Client & Controller")
        self.root.geometry("1100x850") 
        self.root.minsize(800, 600)

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("Treeview.Heading", font=("Helvetica", 10, "bold"))
        self.style.configure("TLabel", font=("Helvetica", 10))
        self.style.configure("TButton", font=("Helvetica", 10, "bold"), foreground="black")
        self.style.configure("Status.TLabel", font=("Helvetica", 9), padding=5)
        self.style.configure("Header.TLabel", font=("Helvetica", 12, "bold"))
        self.style.configure("Active.TLabel", font=("Helvetica", 10, "bold"), foreground="green")
        self.style.configure("Inactive.TLabel", font=("Helvetica", 10, "bold"), foreground="red")
        self.style.configure("Config.TFrame", padding=15)

        self.server_data = []
        self.relay_data = [] 
        self.server_relay_map = {} 
        self._server_by_name = {}
        self.fetch_etags = {}
        self.active_server_info = []
        self.proxy_process = None
        self.proxy_log_tail = collections.deque(maxlen=40)
        self._proxy_log_thread = None
        self._proxy_job_handle = None
        self.tray_broken = False
        self._auto_activation_started = False
        
        self.action_lock = threading.Lock() 
        self.tray_icon = None 
        self.tray_thread = None 
        self.tray_lock = threading.Lock()
        self.app_icon_image = None
        self.icon_path = None
        
        # --- CRITICAL FLAGS ---
        self.is_exiting = False 
        # All persisted-state variables are initialised synchronously below,
        # so saving is safe from the start. (Previously this flag was only
        # flipped after a successful list fetch, which meant an offline user
        # could never save any setting.)
        self.is_initialized = True 

        self.block_ipv6_var = tk.BooleanVar()
        self.require_dnssec_var = tk.BooleanVar()
        self.require_nolog_var = tk.BooleanVar()
        self.require_nofilter_var = tk.BooleanVar()
        self.cache_size_var = tk.StringVar()
        self.cache_neg_ttl_var = tk.StringVar()
        self.cache_min_ttl_var = tk.StringVar()
        self.protocol_filter_var = tk.StringVar()
        
        # Startup / Tray Vars
        self.startup_var = tk.BooleanVar()
        self.start_minimized_var = tk.BooleanVar()

        if getattr(sys, 'frozen', False):
            self.base_path = os.path.dirname(sys.executable)
        else:
            self.base_path = os.path.dirname(os.path.abspath(__file__))
        
        self.data_path = _default_data_directory(self.base_path)
        self.settings_file = os.path.join(self.data_path, SETTINGS_FILE_NAME)
        self.cache_file = os.path.join(self.data_path, CACHE_FILE_NAME)
        self.dns_backup_file = os.path.join(self.data_path, DNS_BACKUP_FILE_NAME)

        # Migrate legacy files that lived next to the executable (portable
        # setups) into the fallback data directory on first run.
        if self.data_path != self.base_path:
            for name in (SETTINGS_FILE_NAME, CACHE_FILE_NAME, DNS_BACKUP_FILE_NAME):
                src = os.path.join(self.base_path, name)
                dst = os.path.join(self.data_path, name)
                if os.path.exists(src) and not os.path.exists(dst):
                    try:
                        shutil.copy2(src, dst)
                    except OSError:
                        LOG.warning("Could not migrate %s: %s", name, src)

        self.settings = self.load_settings() 
        
        # Only auto-reactivate when the proxy was actually running at last
        # shutdown; an explicit Deactivate must stick across restarts.
        if self.settings.get("was_active", False):
            self.preferred_servers = self.settings.get("last_active_servers", [])
        else:
            self.preferred_servers = []
        
        self.protocol_filter_var.set(self.settings.get("ui_filter_protocol", "All Protocols"))
        self.start_minimized_var.set(self.settings.get("ui_start_minimized", False))
        
        self.sort_stack = self.settings.get("ui_sort_stack", [])
        self.sort_dirs = self.settings.get("ui_sort_dirs", {})

        self.block_ipv6_var.set(self.settings.get("block_ipv6", False))
        self.require_dnssec_var.set(self.settings.get("require_dnssec", False))
        self.require_nolog_var.set(self.settings.get("require_nolog", False))
        self.require_nofilter_var.set(self.settings.get("require_nofilter", False))
        self.cache_size_var.set(self.settings.get("cache_size", "512"))
        self.cache_neg_ttl_var.set(self.settings.get("cache_neg_ttl", "60"))
        self.cache_min_ttl_var.set(self.settings.get("cache_min_ttl", "60"))
        self.server_relay_map = self.settings.get("server_relay_map", {})

        # --- Configurable system paths (#3): sensible per-OS defaults ---
        is_windows = platform.system() == "Windows"
        if is_windows:
            _default_cfg_dir = self.base_path
        else:
            _default_cfg_dir = "/etc/dnscrypt-proxy"
        self.proxy_path_var = tk.StringVar(value="")  # resolved by check_proxy_executable()
        self.config_dir_var = tk.StringVar(value=self.settings.get("config_dir", "") or _default_cfg_dir)
        self.engine_version = ""  # populated by _on_version_probe_done
        self._version_probe_thread = None  # single in-flight probe at a time
        # Engine update check: cached for re-application when the version probe
        # lands after the upstream-version check (or vice versa).
        self._engine_update_url = None
        self._engine_release_tag = ""
        self._engine_release_url = ""
        # ETag-based cache for release check requests (reduces GitHub API usage).
        self._gui_release_etag = self.settings.get("gui_release_etag", "") or ""
        self._gui_cached_release_tag = self.settings.get("gui_cached_release_tag", "") or ""
        self._gui_cached_release_url = self.settings.get("gui_cached_release_url", "") or ""
        self._update_url = self.settings.get("gui_update_url", "") or None
        self._engine_release_etag = self.settings.get("engine_release_etag", "") or ""
        self._engine_cached_release_tag = self.settings.get("engine_cached_release_tag", "") or ""
        self._engine_cached_release_url = self.settings.get("engine_cached_release_url", "") or ""
        self._engine_update_url = self.settings.get("engine_update_url", "") or None

        # --- FIX: Recover From a Previous Crashed Session (Threaded) ---
        # Only acts when this app previously changed the DNS and left a
        # backup behind; the user's own manual DNS configuration is never
        # touched on startup.
        def safe_init_cleanup():
            with self.action_lock:
                self.restore_dns_backup()
        threading.Thread(target=safe_init_cleanup, daemon=True).start()

        atexit.register(self.cleanup)
        
        self.load_app_icon()
        self.setup_widgets()
        self.setup_tray_and_close_protocol()

        # Thread-safe bridge for tray callbacks: pystray invokes menu handlers
        # on its own thread, but Tkinter widgets may only be touched from the
        # main thread. Handlers enqueue closures that the main loop drains.
        self._ui_queue = queue.Queue()
        self.root.after(100, self._drain_ui_queue)

        # Apply any release hints we remembered from the previous session so
        # the Configuration tab shows them immediately. The background
        # thread will refresh them.
        self._apply_cached_release_hints()

        # Silent update probe at startup: failures never surface, an
        # available update quietly lights up the Configuration tab row.
        threading.Thread(target=lambda: self._update_check_worker(False),
                         daemon=True, name="update-check").start()

        # Settings-file watcher: detect external edits (config management
        # tools, manual edits) and reload the in-memory state. Skips the
        # change if it is the result of our own save.
        self._settings_watcher_stop = threading.Event()
        self._last_self_save_mtime = 0.0
        try:
            self._last_self_save_mtime = os.path.getmtime(self.settings_file)
        except OSError:
            self._last_self_save_mtime = 0.0
        self._settings_watcher_thread = threading.Thread(
            target=self._settings_file_watcher, daemon=True,
            name="settings-watcher"
        )
        self._settings_watcher_thread.start()

        self.check_proxy_executable()
        self.check_startup_status()

        # --- Window geometry persistence ---
        self._geometry_save_job = None
        saved_geometry = self.settings.get("ui_geometry", "")
        if isinstance(saved_geometry, str) and "x" in saved_geometry:
            try:
                self.root.geometry(saved_geometry)
            except Exception:
                LOG.debug("Could not restore geometry %r", saved_geometry)
        self.root.bind("<Configure>", self._on_window_configure)

        # --- CACHE LOGIC ---
        self.load_server_cache()
        if self.server_data:
            age_message = ""
            if self.server_cache_ts:
                age_minutes = max(0, int((time.time() - self.server_cache_ts) / 60))
                if age_minutes >= 60:
                    age_message = f" (list is {age_minutes // 60}h old)"
                elif age_minutes:
                    age_message = f" (list is {age_minutes} min old)"
            self.status_var.set(f"Loaded {len(self.server_data)} servers from local cache.{age_message}")
            self._populate_tree()
            self.check_auto_activation()
        
        self.start_fetch()
        
        if self.start_minimized_var.get():
            self.hide_window()

    def _get_hidden_subprocess_args(self):
        kwargs = {"text": True, "stdin": subprocess.DEVNULL}
        if platform.system() == "Windows":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            kwargs["startupinfo"] = startupinfo
        return kwargs

    # ------------------------------------------------------------------
    # DNS backup / restore subsystem
    #
    # Before the GUI ever touches system DNS it snapshots the exact current
    # configuration (per adapter on Windows, per network service on macOS,
    # raw resolv.conf state on Linux). Deactivation restores that snapshot
    # verbatim instead of blindly resetting everything to DHCP, which used
    # to destroy manually configured DNS servers.
    # ------------------------------------------------------------------

    def _run_hidden(self, cmd, check=True):
        run_args = self._get_hidden_subprocess_args()
        return subprocess.run(cmd, check=check, capture_output=True, **run_args)

    def _snapshot_dns_windows(self):
        ps = (
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { "
            "$a = (Get-DnsClientServerAddress -InterfaceAlias $_.Name "
            "-AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses; "
            "[PSCustomObject]@{ alias = $_.Name; servers = @($a) } } | "
            "ConvertTo-Json -Compress"
        )
        result = self._run_hidden([
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps
        ])
        output = (result.stdout or "").strip()
        if output:
            try:
                entries = json.loads(output)
            except json.JSONDecodeError:
                raise Exception(
                    f"PowerShell returned unparseable output (not JSON): {output[:200]!r}"
                ) from None
        else:
            entries = []
        if isinstance(entries, dict):
            entries = [entries]
        snapshot = {}
        for entry in entries:
            alias = str(entry.get("alias", "") or "")
            if alias:
                snapshot[alias] = [str(s) for s in (entry.get("servers") or [])]
        if not snapshot:
            raise Exception("No active network adapters with DNS configuration were found.")
        return snapshot

    def _restore_dns_windows(self, snapshot):
        failures = []
        for alias, servers in snapshot.items():
            safe_alias = alias.replace("'", "''")
            if servers:
                addr_list = ", ".join(f"'{s}'" for s in servers)
                ps = (f"Set-DnsClientServerAddress -InterfaceAlias '{safe_alias}' "
                      f"-ServerAddresses {addr_list} -Confirm:$false")
            else:
                ps = f"Reset-DnsClientServerAddress -InterfaceAlias '{safe_alias}' -Confirm:$false"
            result = self._run_hidden(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
                check=False,
            )
            if result.returncode != 0:
                failures.append(alias)
        return failures

    def _list_mac_services(self):
        result = self._run_hidden(["networksetup", "-listallnetworkservices"])
        services = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('*'):
                continue
            if 'denotes' in stripped.lower():
                continue  # legend line, not a service name
            services.append(stripped)
        return services

    def _snapshot_dns_macos(self):
        run_args = self._get_hidden_subprocess_args()
        snapshot = {}
        for service in self._list_mac_services():
            result = subprocess.run(
                ["networksetup", "-getdnsservers", service],
                check=False, capture_output=True, **run_args
            )
            out = (result.stdout or "").strip()
            if not out or out.startswith("There aren't any DNS Servers"):
                snapshot[service] = None  # DHCP-managed; restore to 'empty'
            else:
                snapshot[service] = out.splitlines()
        return snapshot

    def _restore_dns_macos(self, snapshot):
        run_args = self._get_hidden_subprocess_args()
        failures = []
        for service, servers in snapshot.items():
            cmd = ["networksetup", "-setdnsservers", service]
            cmd += list(servers) if servers else ["empty"]
            result = subprocess.run(cmd, check=False, capture_output=True, **run_args)
            if result.returncode != 0:
                failures.append(service)
        return failures

    def _snapshot_dns_linux(self):
        path = "/etc/resolv.conf"
        if not os.path.exists(path):
            return {"exists": False, "is_symlink": False, "target": "", "content": ""}
        is_link = os.path.islink(path)
        with open(path, "rb") as fh:
            content = base64.b64encode(fh.read()).decode("ascii")
        target = os.readlink(path) if is_link else ""
        return {"exists": True, "is_symlink": is_link, "target": target, "content": content}

    def _restore_dns_linux(self, snapshot):
        path = "/etc/resolv.conf"
        try:
            if os.path.lexists(path):
                os.remove(path)
        except OSError:
            pass
        if not snapshot.get("exists"):
            return []
        try:
            if snapshot.get("is_symlink") and snapshot.get("target"):
                os.symlink(snapshot["target"], path)
            else:
                with open(path, "wb") as fh:
                    fh.write(base64.b64decode(snapshot.get("content") or ""))
                os.chmod(path, 0o644)
        except OSError:
            return ["/etc/resolv.conf"]
        return []

    def create_dns_backup(self):
        """Snapshot current system DNS before it is modified.

        Raises when a reliable snapshot cannot be taken so callers can abort
        activation rather than risk an unrestorable change."""
        if os.path.exists(self.dns_backup_file):
            return  # untouched backup from a previous session takes priority
        system = platform.system()
        try:
            if system == "Windows":
                payload = {"platform": system, "adapters": self._snapshot_dns_windows()}
            elif system == "Darwin":
                payload = {"platform": system, "services": self._snapshot_dns_macos()}
            elif system == "Linux":
                payload = {"platform": system, **self._snapshot_dns_linux()}
            else:
                return
        except Exception as e:
            raise Exception(f"Failed to snapshot current DNS settings: {e}") from e
        tmp_path = self.dns_backup_file + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp_path, self.dns_backup_file)

    def restore_dns_backup(self):
        """Restore the exact pre-GUI DNS configuration.

        Returns one of:
          True       — backup existed and was fully applied; backup file removed.
          False      — backup existed but restore was PARTIAL; backup file kept
                       on disk so Restore DNS can be retried. Callers must NOT
                       fall back to reset-to-DHCP in this case.
          None       — no backup existed; nothing to do, nothing to retry.
        Distinguishing "no backup" from "partial restore" lets callers detect
        the corrupt-JSON / "we tried and failed" case without conflating it
        with "fresh install, no backup to begin with"."""
        try:
            with open(self.dns_backup_file, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except FileNotFoundError:
            return None
        except Exception:
            LOG.warning("Corrupt DNS backup at %s", self.dns_backup_file, exc_info=True)
            return False  # corrupt: caller may fall through to DHCP reset
        system = platform.system()
        if payload.get("platform") != system:
            return False  # wrong platform: caller may fall through
        if system == "Windows":
            failures = self._restore_dns_windows(payload.get("adapters", {}))
        elif system == "Darwin":
            failures = self._restore_dns_macos(payload.get("services", {}))
        elif system == "Linux":
            failures = self._restore_dns_linux(payload)
        else:
            failures = []
        if failures:
            LOG.warning(
                "DNS restore incomplete for: %s - keeping %s for retry",
                ", ".join(failures), self.dns_backup_file,
            )
            return False
        try:
            os.remove(self.dns_backup_file)
        except OSError:
            pass
        return True

    def stop_proxy_only(self):
        """Terminate the dnscrypt-proxy child process without any other
        teardown - safe to call from mid-session failure paths."""
        proc = self.proxy_process
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            self.proxy_process = None
        drain = getattr(self, "_proxy_log_thread", None)
        if drain:
            drain.join(timeout=1.0)
            self._proxy_log_thread = None

    def load_app_icon(self):
        potential_paths = []
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
             potential_paths.append(os.path.join(sys._MEIPASS, ICON_FILE))
        potential_paths.append(os.path.join(self.base_path, ICON_FILE))
        potential_paths.append(ICON_FILE)

        for p in potential_paths:
            if os.path.exists(p):
                try:
                    self.icon_path = p
                    self.root.iconbitmap(self.icon_path)
                    if TRAY_AVAILABLE:
                        self.app_icon_image = Image.open(self.icon_path)
                    break
                except Exception:
                    LOG.debug("Could not load app icon from %s", p, exc_info=True)

    def _discover_engine(self):
        """Find the best available dnscrypt-proxy engine.

        Discovery order (first found wins):
          1. User-configured explicit path  → "explicit"
          2. System install on $PATH         → "system"
          3. Bundled engine (app dir / frozen _MEIPASS) → "bundled"
          4. Not found                       → "missing"

        Returns (resolved_path, source_tag).  source is one of:
        "explicit", "system", "bundled", "missing".

        Note: the explicit path is validated for existence/executability; a
        stale or non-runnable entry is downgraded so the caller can fall
        through to a working engine instead of pinning to a broken one."""
        explicit = self.settings.get("proxy_executable_path", "").strip()
        if explicit and self._is_runnable(explicit):
            return explicit, "explicit"

        exe_name = "dnscrypt-proxy" + (".exe" if platform.system() == "Windows" else "")

        system_path = shutil.which(exe_name)
        if system_path:
            return system_path, "system"

        bundled_candidates = [os.path.join(self.base_path, exe_name)]
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            bundled_candidates.insert(0, os.path.join(sys._MEIPASS, exe_name))

        for candidate in bundled_candidates:
            if self._is_runnable(candidate):
                return candidate, "bundled"

        return "", "missing"

    @staticmethod
    def _is_runnable(path):
        """True if `path` is a file and, on POSIX, is marked executable.

        Mirrors the checks `_proxy_available` applies after discovery; kept
        in one place so the "what counts as runnable" policy cannot drift."""
        if not path:
            return False
        if not os.path.isfile(path):
            return False
        if platform.system() == "Windows":
            return True
        return os.access(path, os.X_OK)

    def check_proxy_executable(self):
        path, source = self._discover_engine()
        self.proxy_executable = path
        self.proxy_path_var.set(path)

        if self._proxy_available():
            if source == "system":
                LOG.info("Using system dnscrypt-proxy: %s", path)
            elif source == "bundled":
                LOG.info("Using bundled dnscrypt-proxy: %s", path)
            # Probe the engine version in the background so the UI never
            # blocks on a hung binary. The path is captured in the closure so
            # a newer discovery cannot have its label overwritten by a stale
            # probe from a previous path. An in-flight prior probe's result
            # is dropped by the path-comparison guard in _on_version_probe_done.
            prior = self._version_probe_thread
            if prior is not None and prior.is_alive():
                pass  # prior probe runs to completion; its result is discarded
            self._version_probe_thread = threading.Thread(
                target=lambda p=path: self._post_ui(
                    lambda q=p: self._on_version_probe_done(q)
                ),
                daemon=True, name="version-probe"
            )
            self._version_probe_thread.start()
            self.activate_button.config(state=tk.NORMAL)
        else:
            if source == "explicit":
                msg = (
                    f"The configured path '{path}' could not be found or is not "
                    "executable.\n\nCheck the path on the Configuration tab."
                )
            elif source == "system":
                msg = (
                    "dnscrypt-proxy was found on your system at the default "
                    f"PATH location ({path}), but it could not be executed.\n\n"
                    "Check that the installation is complete, or set a custom "
                    "path on the Configuration tab."
                )
            else:
                msg = (
                    "No dnscrypt-proxy engine was found.\n\n"
                    "The release archive includes one next to the GUI executable. "
                    "If you moved it, re-download the archive. You can also "
                    "install dnscrypt-proxy on your system or set a custom "
                    "path on the Configuration tab."
                )
            messagebox.showwarning("Executable Not Found", msg, parent=self.root)
            self.activate_button.config(state=tk.DISABLED)
            self.engine_version = ""
            label = getattr(self, "engine_version_label", None)
            if label is not None:
                label.config(text="(not found)", foreground="gray", cursor="arrow")

    def _probe_engine_version(self, path):
        """Best-effort `dnscrypt-proxy -version` probe.

        Returns the upstream version string (e.g. "2.1.18") or "" on any
        failure. Runs on a background thread (max 3s) so a hung binary
        cannot block startup."""
        if not path or not self._is_runnable(path):
            return ""
        try:
            run_args = self._get_hidden_subprocess_args()
            proc = subprocess.run(
                [path, "-version"],
                capture_output=True, text=True, timeout=3, **run_args
            )
            out = (proc.stdout or proc.stderr or "").strip()
            # Anchored to the "dnscrypt-proxy" prefix so a stray Go runtime
            # string in stderr cannot be mistaken for the engine version.
            m = re.search(r"dnscrypt-proxy[^0-9]*v?(\d+\.\d+\.\d+)", out, re.IGNORECASE)
            if m:
                return m.group(1)
        except Exception:
            LOG.debug("Engine version probe failed for %s", path, exc_info=True)
        return ""

    def _on_version_probe_done(self, path):
        """UI callback fired once the background version probe completes.

        `path` is the engine path at the moment the probe was scheduled, so
        a discovery made after a re-apply does not get its label overwritten
        by a stale probe from a previous binary.

        The probe is best-effort: a missing or hung binary must never
        disable the activate button or surface an error."""
        # Drop the result if the user has already re-discovered a different
        # engine - the new probe (or none) will refresh the label.
        if path != self.proxy_executable:
            return
        version = self._probe_engine_version(path)
        self.engine_version = version
        label = getattr(self, "engine_version_label", None)
        if label is not None:
            if version:
                label.config(text=version, foreground="", cursor="arrow")
            else:
                label.config(text="(not found)", foreground="gray", cursor="arrow")
        # A new probe may have changed engine_version; if the engine-update
        # check has already run, re-apply its result so the "X -> Y available"
        # or "up to date" verdict reflects the freshly-detected version.
        cached_tag = getattr(self, "_engine_release_tag", None)
        cached_url = getattr(self, "_engine_release_url", None)
        if cached_tag and version:
            self._apply_engine_update_result(cached_tag, cached_url)

    def _proxy_available(self):
        """True when the configured proxy can actually be launched."""
        return self._is_runnable(getattr(self, 'proxy_executable', ''))

    def setup_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        activation_frame = ttk.Frame(main_frame, padding=5, relief=tk.RIDGE)
        activation_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.activate_button = ttk.Button(activation_frame, text="Activate Selected Server(s)", command=self.toggle_activation, state=tk.DISABLED)
        self.activate_button.pack(side=tk.RIGHT, padx=(5, 10), pady=5)
        self.restart_button = ttk.Button(
            activation_frame, text="Restart Proxy", command=self.update_config_and_restart_proxy,
            state=tk.DISABLED, width=13,
        )
        self.restart_button.pack(side=tk.RIGHT, padx=5, pady=5)
        
        startup_check = ttk.Checkbutton(activation_frame, text="Run at system startup", variable=self.startup_var, command=self.toggle_startup)
        startup_check.pack(side=tk.RIGHT, padx=5)

        minimized_check = ttk.Checkbutton(activation_frame, text="Start minimized to tray", variable=self.start_minimized_var, command=self.save_settings)
        minimized_check.pack(side=tk.RIGHT, padx=10)

        self.status_indicator = ttk.Label(activation_frame, text="STATUS: INACTIVE", style="Inactive.TLabel")
        self.status_indicator.pack(side=tk.LEFT, padx=10)

        self.active_server_label = ttk.Label(activation_frame, text="No server active.")
        self.active_server_label.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=10)

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        servers_tab = ttk.Frame(notebook, padding=10)
        notebook.add(servers_tab, text="Servers")
        
        top_frame = ttk.Frame(servers_tab)
        top_frame.pack(fill=tk.X, pady=(0, 5))
        
        filter_frame = ttk.Frame(top_frame)
        filter_frame.pack(side=tk.LEFT)
        ttk.Label(filter_frame, text="Filter Protocol: ").pack(side=tk.LEFT)
        self.proto_combo = ttk.Combobox(filter_frame, textvariable=self.protocol_filter_var, state="readonly", 
                                        values=["All Protocols", "DNSCrypt", "DoH"], width=15)
        self.proto_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.proto_combo.bind("<<ComboboxSelected>>", self.on_filter_changed)

        btn_frame = ttk.Frame(top_frame)
        btn_frame.pack(side=tk.RIGHT)
        
        self.bridge_button = ttk.Button(btn_frame, text="Set/Change Relay", command=self.open_bridge_selector, state=tk.DISABLED)
        self.bridge_button.pack(side=tk.LEFT, padx=5)
        
        self.fetch_button = ttk.Button(btn_frame, text="Refresh Server List", command=self.start_fetch)
        self.fetch_button.pack(side=tk.LEFT)

        tree_frame = ttk.Frame(servers_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        columns = ("name", "type", "via", "no-log", "dnssec", "no-filter")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="extended")

        # Zebra rows derived from the active theme so they stay readable on
        # dark system themes instead of hard-coding light colors.
        theme_bg = self.style.lookup('Treeview', 'background') or '#ffffff'

        if self._luminance(theme_bg) >= 0.5:
            odd_bg, even_bg = '#f0f0f0', 'white'
        else:
            odd_bg, even_bg = '#2a2d32', '#1e2126'
        self.tree.tag_configure('oddrow', background=odd_bg)
        self.tree.tag_configure('evenrow', background=even_bg)
        
        self.tree.heading("name", text="Server Name", command=lambda: self.on_header_click("name"))
        self.tree.column("name", width=220, stretch=tk.YES)
        self.tree.heading("type", text="Protocol", command=lambda: self.on_header_click("type"))
        self.tree.column("type", width=80, anchor=tk.CENTER)
        self.tree.heading("via", text="via Relay(s)", command=lambda: self.on_header_click("via"))
        self.tree.column("via", width=150, stretch=tk.YES, anchor=tk.W)
        self.tree.heading("no-log", text="No Logs", command=lambda: self.on_header_click("no-log"))
        self.tree.column("no-log", width=60, anchor=tk.CENTER)
        self.tree.heading("dnssec", text="DNSSEC", command=lambda: self.on_header_click("dnssec"))
        self.tree.column("dnssec", width=60, anchor=tk.CENTER)
        self.tree.heading("no-filter", text="No Filter", command=lambda: self.on_header_click("no-filter"))
        self.tree.column("no-filter", width=60, anchor=tk.CENTER)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y"); hsb.pack(side="bottom", fill="x"); self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_server_select)
        
        bottom_frame = ttk.Frame(servers_tab, padding=(0, 10, 0, 0))
        bottom_frame.pack(fill=tk.BOTH, expand=True, side=tk.BOTTOM)
        ttk.Label(bottom_frame, text="Selected Server Details:", style="Header.TLabel").pack(anchor=tk.W, pady=(10, 5))
        self.details_text = scrolledtext.ScrolledText(bottom_frame, height=8, wrap=tk.WORD, font=("Courier", 10))
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.details_text.insert(tk.END, "Select a server to see details.")
        self.details_text.configure(state='disabled')

        config_tab = ttk.Frame(notebook, style="Config.TFrame")
        notebook.add(config_tab, text="Configuration")
        self._create_config_tab(config_tab)
        
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, style="Status.TLabel", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var.set("Ready.")

    def _create_config_tab(self, parent):
        paths_frame = ttk.LabelFrame(parent, text="System Paths", padding=10)
        paths_frame.pack(fill=tk.X, pady=5, padx=5)

        proxy_row = ttk.Frame(paths_frame); proxy_row.pack(fill=tk.X, pady=3)
        ttk.Label(proxy_row, text="dnscrypt-proxy executable:", width=24).pack(side=tk.LEFT)
        ttk.Entry(proxy_row, textvariable=self.proxy_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(proxy_row, text="Browse...",
                   command=lambda: self._browse_path(self.proxy_path_var, "file")).pack(side=tk.RIGHT)

        cfgdir_row = ttk.Frame(paths_frame); cfgdir_row.pack(fill=tk.X, pady=3)
        ttk.Label(cfgdir_row, text="Configuration folder:", width=24).pack(side=tk.LEFT)
        ttk.Entry(cfgdir_row, textvariable=self.config_dir_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(cfgdir_row, text="Browse...",
                   command=lambda: self._browse_path(self.config_dir_var, "dir")).pack(side=tk.RIGHT)

        ttk.Button(paths_frame, text="Apply & Restart Proxy",
                   command=self._apply_paths_and_restart).pack(anchor=tk.E, pady=(5, 0))

        req_frame = ttk.LabelFrame(parent, text="Server Requirements", padding=10)
        req_frame.pack(fill=tk.X, pady=5, padx=5)
        
        ttk.Checkbutton(req_frame, text="Require servers to support DNSSEC", variable=self.require_dnssec_var, command=self.update_config_and_restart_proxy).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(req_frame, text="Require servers to be non-logging", variable=self.require_nolog_var, command=self.update_config_and_restart_proxy).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(req_frame, text="Require servers to be non-filtering", variable=self.require_nofilter_var, command=self.update_config_and_restart_proxy).pack(anchor=tk.W, pady=2)

        net_frame = ttk.LabelFrame(parent, text="Network Behavior", padding=10)
        net_frame.pack(fill=tk.X, pady=5, padx=5)
        ttk.Checkbutton(net_frame, text="Block IPv6 DNS requests", variable=self.block_ipv6_var, command=self.update_config_and_restart_proxy).pack(anchor=tk.W, pady=2)

        cache_frame = ttk.LabelFrame(parent, text="Cache Configuration", padding=10)
        cache_frame.pack(fill=tk.X, pady=5, padx=5)

        size_frame = ttk.Frame(cache_frame); size_frame.pack(fill=tk.X, pady=3)
        # dnscrypt-proxy's cache_size counts cache ENTRIES, not bytes.
        ttk.Label(size_frame, text="Cache size (entries):", width=25).pack(side=tk.LEFT)
        size_entry = ttk.Entry(size_frame, textvariable=self.cache_size_var, width=15)
        size_entry.pack(side=tk.LEFT, padx=5)
        size_entry.bind("<FocusOut>", lambda e: self._validated_cache_apply(
            self.cache_size_var, CACHE_SIZE_DEFAULT, CACHE_SIZE_MIN, CACHE_SIZE_MAX, "Cache size"))

        min_ttl_frame = ttk.Frame(cache_frame); min_ttl_frame.pack(fill=tk.X, pady=3)
        ttk.Label(min_ttl_frame, text="Cache min TTL (seconds):", width=25).pack(side=tk.LEFT)
        min_ttl_entry = ttk.Entry(min_ttl_frame, textvariable=self.cache_min_ttl_var, width=15)
        min_ttl_entry.pack(side=tk.LEFT, padx=5)
        min_ttl_entry.bind("<FocusOut>", lambda e: self._validated_cache_apply(
            self.cache_min_ttl_var, CACHE_TTL_DEFAULT, CACHE_TTL_MIN, CACHE_TTL_MAX, "Cache min TTL"))

        neg_ttl_frame = ttk.Frame(cache_frame); neg_ttl_frame.pack(fill=tk.X, pady=3)
        ttk.Label(neg_ttl_frame, text="Cache negative TTL (seconds):", width=25).pack(side=tk.LEFT)
        neg_ttl_entry = ttk.Entry(neg_ttl_frame, textvariable=self.cache_neg_ttl_var, width=15)
        neg_ttl_entry.pack(side=tk.LEFT, padx=5)
        neg_ttl_entry.bind("<FocusOut>", lambda e: self._validated_cache_apply(
            self.cache_neg_ttl_var, CACHE_TTL_DEFAULT, CACHE_TTL_MIN, CACHE_TTL_MAX, "Cache negative TTL"))

        ttk.Label(parent, text="Changes are applied immediately if the service is active.", style="Status.TLabel").pack(pady=(14, 4))

        updates_frame = ttk.LabelFrame(parent, text="Updates", padding=10)
        updates_frame.pack(fill=tk.X, pady=5, padx=5, side=tk.BOTTOM, anchor=tk.S)

        gui_ver_row = ttk.Frame(updates_frame)
        gui_ver_row.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(gui_ver_row, text="GUI version:", width=16, anchor=tk.W).pack(side=tk.LEFT)
        self.gui_version_label = ttk.Label(gui_ver_row, text=f"v{APP_VERSION}",
                                          font=("", 9, "bold"), anchor=tk.W)
        self.gui_version_label.pack(side=tk.LEFT, padx=(0, 8))
        self.update_status_label = ttk.Label(gui_ver_row, text="up to date",
                                            style="Status.TLabel", anchor=tk.W)
        self.update_status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.update_status_label.bind("<Button-1>", self._open_update_link)
        self.gui_version_label.bind("<Button-1>", self._open_update_link)

        engine_ver_row = ttk.Frame(updates_frame)
        engine_ver_row.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(engine_ver_row, text="Engine version:", width=16, anchor=tk.W).pack(side=tk.LEFT)
        self._engine_update_url = None
        self.engine_version_label = ttk.Label(engine_ver_row, text="(probing...)",
                                             font=("", 9, "bold"), foreground="gray",
                                             anchor=tk.W, cursor="arrow")
        self.engine_version_label.pack(side=tk.LEFT, padx=(0, 8), fill=tk.X, expand=True)
        self.engine_version_label.bind("<Button-1>", self._open_engine_update_link)

        btn_row = ttk.Frame(updates_frame)
        btn_row.pack(fill=tk.X)
        self._update_url = None
        self.check_updates_button = ttk.Button(btn_row, width=20,
                                               text="Check for updates",
                                               command=self.manual_update_check)
        self.check_updates_button.pack(side=tk.LEFT)

    def _browse_path(self, target_var, kind):
        if kind == "file":
            chosen = filedialog.askopenfilename(
                title="Select dnscrypt-proxy executable",
                parent=self.root,
            )
        else:
            chosen = filedialog.askdirectory(title="Select configuration folder", parent=self.root)
        if chosen:
            target_var.set(chosen)
            self.save_settings()

    def _apply_paths_and_restart(self):
        self.save_settings()
        self.check_proxy_executable()
        if self.active_server_info:
            self.update_config_and_restart_proxy()
        else:
            self.status_var.set("Paths saved.")

    def save_settings(self):
        if self.is_exiting or not self.is_initialized:
            return
        
        servers_to_save = [s['name'] for s in self.active_server_info]

        settings_to_save = {
            "was_active": bool(self.active_server_info),
            "last_active_servers": servers_to_save,
            "server_relay_map": self.server_relay_map,
            "ui_filter_protocol": self.protocol_filter_var.get(),
            "ui_start_minimized": self.start_minimized_var.get(),
            "ui_geometry": (self.root.geometry()
                            if self.root.state() == "normal"
                            else self.settings.get("ui_geometry", "")),
            "ui_sort_stack": self.sort_stack,
            "ui_sort_dirs": self.sort_dirs,
            "block_ipv6": self.block_ipv6_var.get(),
            "require_dnssec": self.require_dnssec_var.get(),
            "require_nolog": self.require_nolog_var.get(),
            "require_nofilter": self.require_nofilter_var.get(),
            "cache_size": self.cache_size_var.get(),
            "cache_neg_ttl": self.cache_neg_ttl_var.get(),
            "cache_min_ttl": self.cache_min_ttl_var.get(),
            "proxy_executable_path": self.proxy_path_var.get(),
            "config_dir": self.config_dir_var.get(),
            # Release check cache: avoids a network round-trip on cold start so
            # the Configuration tab can immediately show update hints from the
            # previous session. Etags reduce GitHub API usage on repeat calls.
            "gui_release_etag": getattr(self, "_gui_release_etag", "") or "",
            "gui_cached_release_tag": getattr(self, "_gui_cached_release_tag", "") or "",
            "gui_cached_release_url": getattr(self, "_gui_cached_release_url", "") or "",
            "gui_update_url": getattr(self, "_update_url", "") or "",
            "engine_release_etag": getattr(self, "_engine_release_etag", "") or "",
            "engine_cached_release_tag": getattr(self, "_engine_cached_release_tag", "") or "",
            "engine_cached_release_url": getattr(self, "_engine_cached_release_url", "") or "",
            "engine_update_url": getattr(self, "_engine_update_url", "") or "",
        }
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings_to_save, f, indent=4)
            try:
                # Bump the recorded mtime slightly ahead of the file's
                # recorded value. Some filesystems (notably FAT/exFAT on
                # Windows) round mtime to a 2s boundary, so reading the
                # mtime immediately after writing can yield a value that
                # is *less* than the actual write time, causing the
                # watcher to think our own save was an external edit.
                mtime = os.path.getmtime(self.settings_file)
                self._last_self_save_mtime = mtime + 0.5
            except OSError:
                pass
        except OSError as e:
            LOG.warning("Could not save settings to %s: %s", self.settings_file, e)
        except Exception as e:
            LOG.error("Unexpected error saving settings to %s: %s", self.settings_file, e)

    def load_settings(self):
        try:
            with open(self.settings_file, 'r') as f: return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                "was_active": False, "last_active_servers": [], "server_relay_map": {},
                "ui_filter_protocol": "All Protocols", "ui_start_minimized": False, "ui_sort_stack": [], "ui_sort_dirs": {},
                "block_ipv6": False, "require_dnssec": False, "require_nolog": False,
                "require_nofilter": False, "cache_size": "512", "cache_neg_ttl": "60", "cache_min_ttl": "60"
            }

    def _settings_file_watcher(self):
        while not self._settings_watcher_stop.is_set():
            # Wake up to 1s early on shutdown rather than waiting the full sleep.
            if self._settings_watcher_stop.wait(timeout=5):
                break
            try:
                current_mtime = os.path.getmtime(self.settings_file)
            except OSError:
                continue
            if current_mtime == self._last_self_save_mtime:
                continue
            self._post_ui(self._reload_settings_from_disk)

    def _reload_settings_from_disk(self):
        try:
            with open(self.settings_file) as f:
                fresh = json.load(f)
        except Exception:
            return
        # Merge fresh file into in-memory state.
        self.settings.update(fresh)
        # Update GUI-facing variables from fresh settings.
        protocol = fresh.get("ui_filter_protocol", "All Protocols")
        try:
            self.protocol_filter_var.set(protocol)
        except tk.TclError:
            pass
        for attr, key in [
            ("block_ipv6_var", "block_ipv6"),
            ("require_dnssec_var", "require_dnssec"),
            ("require_nolog_var", "require_nolog"),
            ("require_nofilter_var", "require_nofilter"),
        ]:
            w = getattr(self, attr, None)
            if w is not None:
                try:
                    w.set(fresh.get(key, False))
                except tk.TclError:
                    pass
        for attr, key in [("cache_size_var", "cache_size"),
                          ("cache_neg_ttl_var", "cache_neg_ttl"),
                          ("cache_min_ttl_var", "cache_min_ttl")]:
            w = getattr(self, attr, None)
            if w is not None:
                val = fresh.get(key, "")
                try:
                    w.set(val)
                except tk.TclError:
                    pass
        proxy_path = fresh.get("proxy_executable_path", "")
        if proxy_path:
            try:
                self.proxy_path_var.set(proxy_path)
            except tk.TclError:
                pass
        config_dir = fresh.get("config_dir", "")
        if config_dir:
            try:
                self.config_dir_var.set(config_dir)
            except tk.TclError:
                pass
        # Refresh release hint labels if fresh data is available.
        self._apply_cached_release_hints()
        LOG.info("Settings reloaded from disk (external edit detected)")

    def save_server_cache(self):
        if not self.server_data: return
        cache_data = {
            "servers": self.server_data,
            "relays": self.relay_data,
            "etags": self.fetch_etags,
            "timestamp": time.time()
        }
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f)
        except Exception as e:
            LOG.error("Failed to save server cache: %s", e)

    def load_server_cache(self):
        self.server_cache_ts = None
        try:
            if not os.path.exists(self.cache_file): return False
            with open(self.cache_file, 'r') as f:
                data = json.load(f)
                self.server_data = self._dedupe_by_name(data.get("servers", []))
                self.relay_data = self._dedupe_by_name(data.get("relays", []))
                self.fetch_etags = data.get("etags", {})
                self._server_by_name = {s["name"]: s for s in self.server_data}
                self.server_cache_ts = data.get("timestamp")
                return True
        except Exception:
            LOG.debug("Could not load server cache", exc_info=True)
            return False

    @staticmethod
    def _dedupe_by_name(items):
        """Drop entries with missing or duplicated names, keeping the first.

        Treeview rows and config static-sections are keyed by name, so a
        duplicated entry from an upstream mirror or a corrupted cache would
        raise TclError at populate time and break the whole server table."""
        seen = set()
        unique = []
        for item in items:
            name = item.get("name") if isinstance(item, dict) else None
            if not name or name in seen:
                LOG.warning("Dropping resolver entry with %s name: %r",
                            "missing" if not name else "duplicate", name)
                continue
            seen.add(name)
            unique.append(item)
        return unique

    def setup_tray_and_close_protocol(self):
        self.root.protocol('WM_DELETE_WINDOW', self.on_close_window)

    def on_close_window(self):
        if not TRAY_AVAILABLE or getattr(self, "tray_broken", False):
            # No working tray icon exists, so closing must not silently
            # strand the app as an unminimizable ghost - ask explicitly.
            if messagebox.askyesno(
                    "Exit DNSCrypt Client?",
                    "The system tray icon is unavailable.\n"
                    "Closing this window will EXIT the application\n"
                    "(and deactivate the proxy). Continue?", parent=self.root):
                self.quit_app()
            else:
                self.root.iconify()
            return
        self.hide_window()

    def _on_window_configure(self, event):
        if event.widget is not self.root:
            return
        if self._geometry_save_job:
            self.root.after_cancel(self._geometry_save_job)
        self._geometry_save_job = self.root.after(800, self._persist_geometry)

    def _persist_geometry(self):
        self._geometry_save_job = None
        try:
            if not self.is_exiting and self.root.state() == "normal":
                self.save_settings()
        except Exception:
            LOG.debug("Could not persist window geometry", exc_info=True)

    def _post_ui(self, fn):
        self._ui_queue.put(fn)

    def _drain_ui_queue(self):
        try:
            while True:
                fn = self._ui_queue.get_nowait()
                try:
                    fn()
                except Exception:
                    LOG.debug("UI-queue callback failed", exc_info=True)
        except queue.Empty:
            pass
        try:
            self.root.after(100, self._drain_ui_queue)
        except tk.TclError:
            pass  # window destroyed - the loop dies with it

    def hide_window(self):
        if not TRAY_AVAILABLE or getattr(self, "tray_broken", False):
            # No working system-tray backend - minimising keeps the app
            # reachable from the taskbar instead of hiding it.
            self.root.iconify()
            return
        self.root.withdraw()
        def start_icon_thread():
            try:
                image = self.app_icon_image if self.app_icon_image else Image.new('RGB', (64, 64), 'green')
                menu = (item('Show', self.show_window, default=True), item('Exit', self.quit_app))
                with self.tray_lock: self.tray_icon = icon(APP_NAME, image, "DNSCrypt Client", menu)
                self.tray_icon.run()
                with self.tray_lock: self.tray_icon = None
            except Exception:
                # Quitting here would silently deactivate a running proxy;
                # degrade to taskbar mode and let the user stay in control.
                LOG.error("Tray icon crashed - falling back to taskbar mode",
                          exc_info=True)
                self.tray_broken = True
                self._post_ui(lambda: self.root.iconify())

        with self.tray_lock:
            if not (self.tray_thread and self.tray_thread.is_alive()):
                self.tray_thread = threading.Thread(target=start_icon_thread, daemon=True)
                self.tray_thread.start()

    def show_window(self):
        with self.tray_lock:
            if self.tray_icon: self.tray_icon.stop()

        def _show():
            self.root.deiconify()
            self.root.lift()
            self.root.attributes('-topmost', 1)
            self.root.attributes('-topmost', 0)

        # Called by pystray on its own thread - marshal into the Tk loop.
        self._post_ui(_show)

    def quit_app(self):
        with self.tray_lock:
            if self.tray_icon: self.tray_icon.stop()
        self._post_ui(self.root.destroy)

    @staticmethod
    def _xml_escape(text):
        return (text.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;"))

    @staticmethod
    def _desktop_quote(token):
        """Quote a token for a .desktop Exec= line.

        Inside double quotes the spec only treats \\" and \\\\ specially;
        %% escapes what would otherwise parse as a field code."""
        escaped = token.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
        return f'"{escaped}"'

    def get_startup_tokens(self):
        """Argument tokens that relaunch this app for autostart entries.

        Frozen builds must launch the executable itself - registering it
        twice ('exe exe') used to work by accident but is wrong; script
        runs need the interpreter plus the script path."""
        if getattr(sys, "frozen", False):
            return [sys.executable]
        return [sys.executable, os.path.abspath(sys.argv[0])]

    def toggle_startup(self):
        if self.startup_var.get(): self.add_to_startup()
        else: self.remove_from_startup()

    def add_to_startup(self):
        system = platform.system()
        try:
            if system == "Windows":
                command = " ".join(f'"{t}"' for t in self.get_startup_tokens())
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, command)
            elif system == "Linux":
                autostart_path = os.path.expanduser("~/.config/autostart")
                os.makedirs(autostart_path, exist_ok=True)
                desktop_file_path = os.path.join(autostart_path, f"{APP_NAME}.desktop")
                exec_line = " ".join(self._desktop_quote(t) for t in self.get_startup_tokens())
                with open(desktop_file_path, "w") as f:
                    f.write(f"[Desktop Entry]\nType=Application\nExec={exec_line}\nX-GNOME-Autostart-enabled=true\nName={APP_NAME}\n")
            elif system == "Darwin":
                agent_path = os.path.expanduser(f"~/Library/LaunchAgents/com.{APP_NAME}.plist")
                args_xml = "".join(
                    f"<string>{self._xml_escape(t)}</string>" for t in self.get_startup_tokens()
                )
                plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.{APP_NAME}</string>
<key>ProgramArguments</key><array>{args_xml}</array>
<key>RunAtLoad</key><true/>
</dict></plist>"""
                with open(agent_path, "w") as f: f.write(plist_content)
        except Exception as e:
            messagebox.showerror("Startup Error", f"Failed to add to startup: {e}")

    def remove_from_startup(self):
        system = platform.system()
        try:
            if system == "Windows":
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, APP_NAME)
            elif system == "Linux":
                desktop_file_path = os.path.expanduser(f"~/.config/autostart/{APP_NAME}.desktop")
                if os.path.exists(desktop_file_path): os.remove(desktop_file_path)
            elif system == "Darwin":
                agent_path = os.path.expanduser(f"~/Library/LaunchAgents/com.{APP_NAME}.plist")
                if os.path.exists(agent_path): os.remove(agent_path)
        except FileNotFoundError: pass
        except Exception as e:
            messagebox.showerror("Startup Error", f"Failed to remove from startup: {e}")

    def check_startup_status(self):
        system = platform.system()
        is_startup = False
        try:
            if system == "Windows":
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                    winreg.QueryValueEx(key, APP_NAME); is_startup = True
            elif system == "Linux":
                is_startup = os.path.exists(os.path.expanduser(f"~/.config/autostart/{APP_NAME}.desktop"))
            elif system == "Darwin":
                is_startup = os.path.exists(os.path.expanduser(f"~/Library/LaunchAgents/com.{APP_NAME}.plist"))
        except Exception:
            LOG.debug("Startup registration check failed", exc_info=True)
            is_startup = False
        self.startup_var.set(is_startup)
    
    def on_filter_changed(self, event=None):
        self._populate_tree()
        self.save_settings()

    def on_header_click(self, col):
        if self.sort_stack and self.sort_stack[-1] == col:
            current_dir = self.sort_dirs.get(col, False)
            self.sort_dirs[col] = not current_dir
        else:
            self.sort_dirs[col] = False 
            if col in self.sort_stack: self.sort_stack.remove(col)
            self.sort_stack.append(col)
        self.apply_current_sorts()
        self.save_settings()

    def apply_current_sorts(self):
        if not self.sort_stack: return
        iids = self.tree.get_children('')
        data_rows = []
        for iid in iids:
            row_data = {col: self.tree.set(iid, col) for col in self.tree["columns"]}
            data_rows.append((iid, row_data))
        for col in self.sort_stack:
            reverse = self.sort_dirs.get(col, False)
            data_rows.sort(key=lambda x: str(x[1][col]).lower(), reverse=reverse)
        
        for index, (iid, _) in enumerate(data_rows):
            self.tree.move(iid, '', index)
            tag = 'oddrow' if index % 2 != 0 else 'evenrow'
            self.tree.item(iid, tags=(tag,))
            
        for c in self.tree["columns"]:
            clean_text = self.tree.heading(c, "text").replace(" ▲", "").replace(" ▼", "")
            self.tree.heading(c, text=clean_text)
        primary_col = self.sort_stack[-1]
        reverse = self.sort_dirs.get(primary_col, False)
        new_text = f"{self.tree.heading(primary_col, 'text')} {'▼' if reverse else '▲'}"
        self.tree.heading(primary_col, text=new_text)

    def _populate_tree(self, server_list=None):
        if server_list is None: server_list = self.server_data
        filter_val = self.protocol_filter_var.get()
        filtered_list = []
        for server in server_list:
            if filter_val == "All Protocols": filtered_list.append(server)
            elif filter_val == "DNSCrypt" and server.get('proto_type') == 'DNSCrypt': filtered_list.append(server)
            elif filter_val == "DoH" and server.get('proto_type') == 'DoH': filtered_list.append(server)
        
        self.tree.delete(*self.tree.get_children())
        for i, server in enumerate(filtered_list):
            relays = self.server_relay_map.get(server["name"], [])
            if isinstance(relays, str): relays = [relays] if relays else []
            if not isinstance(relays, list): relays = []
            values = self._tree_values(server, ", ".join(relays))

            tag = 'oddrow' if i % 2 != 0 else 'evenrow'
            self.tree.insert("", tk.END, values=values, iid=server["name"], tags=(tag,))

        self.status_var.set(f"Showing {len(filtered_list)} servers ({len(self.server_data)} total) and {len(self.relay_data)} relays.")
        self.apply_current_sorts()

    @staticmethod
    def _luminance(color):
        """Perceived luminance (0..1) of a #rgb / #rrggbb color; 1.0 when
        unparseable so callers default to light-theme assumptions."""
        color = str(color).lstrip('#')
        if len(color) == 3:
            color = ''.join(c * 2 for c in color)
        try:
            r, g, b = (int(color[i:i + 2], 16) for i in (0, 2, 4))
        except ValueError:
            return 1.0
        return (0.299 * r + 0.587 * g + 0.114 * b) / 255

    @staticmethod
    def _tree_values(server, relays_display):
        """Row tuple for the server table.

        Uses defaults for fields a cache file may predate, so a partial or
        hand-edited cache can never raise KeyError at populate time."""
        return (server["name"],
                server.get("proto_type", "?"),
                relays_display,
                server.get("no-log", "\u2717"),
                server.get("dnssec", "\u2717"),
                server.get("no-filter", "\u2717"))

    # ------------------------------------------------------------------
    # Update check (semver-aware, unobtrusive)
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_semver(tag):
        """Parse 'vX.Y.Z' into an (int, int, int) tuple; None if malformed.

        Pre-release/build suffixes ('-beta.1', '+build') are stripped: the
        project ships only final releases, so base triples decide ordering.
        Leading zeros are tolerated and normalised by int()."""
        if not isinstance(tag, str):
            return None
        base = tag.strip().lstrip("vV").split("-", 1)[0].split("+", 1)[0]
        parts = base.split(".")
        if len(parts) != 3:
            return None
        try:
            nums = tuple(int(p) for p in parts)
        except ValueError:
            return None
        return nums

    @staticmethod
    def _evaluate_update(tag, current):
        """Classify the latest remote tag against the running version.

        Returns (kind, display, url) where kind is one of
        'available' | 'current' | 'invalid'."""
        candidate = DNSCryptClientGUI._parse_semver(tag)
        running = DNSCryptClientGUI._parse_semver(current)
        if not tag or not candidate or not running:
            return ("invalid", "", RELEASES_PAGE)
        if candidate > running:
            display = "v{}.{}.{}".format(*candidate)
            return ("available", display, RELEASES_PAGE)
        return ("current", f"v{running[0]}.{running[1]}.{running[2]}", "")

    def _fetch_latest_release(self):
        """Query GitHub for the latest published GUI release.

        Returns (tag, html_url), or (None, None) on any failure - callers
        treat that as 'check failed' rather than 'up to date'.

        Uses the ETag stored on the instance (from a previous fetch) to send
        an If-None-Match conditional GET; a 304 response reuses the cached
        (tag, url) without re-parsing JSON."""
        return self._fetch_release_with_etag(
            LATEST_RELEASE_API, RELEASES_PAGE,
            etag_attr="_gui_release_etag",
            cache_tag_attr="_gui_cached_release_tag",
            cache_url_attr="_gui_cached_release_url",
            log_label="GUI",
        )

    def _fetch_latest_engine_release(self):
        """Query GitHub for the latest upstream dnscrypt-proxy release.

        Returns (tag, html_url), or (None, None) on any failure. Same
        conditional-GET pattern as _fetch_latest_release."""
        return self._fetch_release_with_etag(
            LATEST_ENGINE_RELEASE_API, ENGINE_RELEASES_PAGE,
            etag_attr="_engine_release_etag",
            cache_tag_attr="_engine_cached_release_tag",
            cache_url_attr="_engine_cached_release_url",
            log_label="Engine",
        )

    def _fetch_release_with_etag(self, url, fallback_page, etag_attr,
                                  cache_tag_attr, cache_url_attr, log_label):
        """Shared fetch helper with ETag-based conditional GET support.

        On 304 Not Modified, returns the previously cached (tag, html_url)
        from cache_tag_attr/cache_url_attr without re-parsing JSON. On 200,
        updates the cache and stores the new ETag in etag_attr. On any other
        failure (timeout, network error, non-2xx) returns (None, None) so
        the caller can treat it as 'check inconclusive'."""
        try:
            import requests
            headers = {
                "User-Agent": f"{APP_NAME}/{APP_VERSION}",
                "Accept": "application/vnd.github+json",
            }
            cached_etag = getattr(self, etag_attr, "") or ""
            if cached_etag:
                headers["If-None-Match"] = cached_etag
            resp = requests.get(url, timeout=10, headers=headers)
            if resp.status_code == 304:
                cached_tag = getattr(self, cache_tag_attr, "") or ""
                cached_url = getattr(self, cache_url_attr, "") or ""
                if cached_tag and cached_url:
                    return cached_tag, cached_url
                # 304 without a cached payload is a server contract violation;
                # clear the stored ETag so we don't send it on the re-fetch
                # or on future calls.
                setattr(self, etag_attr, "")
                try:
                    del headers["If-None-Match"]
                except KeyError:
                    pass
                resp = requests.get(url, timeout=10, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict):
                return None, None
            tag = data.get("tag_name") or ""
            safe = self._safe_url(data.get("html_url"), fallback_page)
            if tag and safe:
                new_etag = resp.headers.get("ETag", "") or ""
                setattr(self, etag_attr, new_etag)
                setattr(self, cache_tag_attr, tag)
                setattr(self, cache_url_attr, safe)
            return tag, safe
        except Exception:
            LOG.debug("%s release check failed", log_label, exc_info=True)
            return None, None

    @staticmethod
    def _safe_url(value, fallback):
        """Coerce an untrusted URL field to an http(s) string; else fallback.

        GitHub occasionally returns null or unexpected types in release JSON;
        we must not feed a list, dict, or non-string into webbrowser.open()."""
        if not isinstance(value, str) or not value:
            return fallback
        if not value.startswith(("http://", "https://")):
            return fallback
        return value

    def _update_check_worker(self, notify_on_failure):
        # Tests set this env var so they never phone home.
        if os.environ.get("DNSCRYPT_GUI_SKIP_UPDATE_CHECK"):
            self._post_ui(lambda: self._re_enable_update_button(notify_on_failure, skipped=True))
            return
        # Two independent checks; each owns its own result label.
        gui_tag, gui_url = self._fetch_latest_release()
        engine_tag, engine_url = self._fetch_latest_engine_release()

        def done():
            try:
                self._apply_update_result(gui_tag, gui_url, notify_on_failure)
                self._apply_engine_update_result(engine_tag, engine_url, notify_on_failure)
            finally:
                self._re_enable_update_button(notify_on_failure)
            self._save_release_settings()

        self._post_ui(done)

    def _re_enable_update_button(self, notify_on_failure, skipped=False):
        button = getattr(self, "check_updates_button", None)
        if button is not None:
            try:
                button.state(["!disabled"])
            except tk.TclError:
                pass
        if skipped and notify_on_failure:
            self.status_var.set("Update check skipped (test mode).")

    def _apply_cached_release_hints(self):
        """Apply release hints persisted from the previous session.

        Called synchronously on startup so the Configuration tab shows meaningful
        labels before the background network check completes. No-op if no cache
        was persisted (first run or offline shutdown)."""
        gui_tag = getattr(self, "_gui_cached_release_tag", "") or ""
        gui_url = getattr(self, "_gui_cached_release_url", "") or ""
        engine_tag = getattr(self, "_engine_cached_release_tag", "") or ""
        engine_url = getattr(self, "_engine_cached_release_url", "") or ""
        if gui_tag:
            self._apply_update_result(gui_tag, gui_url, notify_on_failure=False)
        if engine_tag:
            self._apply_engine_update_result(engine_tag, engine_url, notify_on_failure=False)

    def _save_release_settings(self):
        """Update in-memory settings with release check cache.

        Called after each update check. A failed network check that returned
        (None, None) does NOT overwrite previously cached values — the
        instance attributes still hold the last successful result. Only non-None
        values are written so a stale cache is never accidentally cleared."""
        if getattr(self, "is_exiting", False) or not getattr(self, "is_initialized", False):
            return
        update = {}
        # ETag attributes are intentionally always written: an empty ETag means
        # "no server cache key" and that is valid state we want persisted.
        for key, attr in [
            ("gui_release_etag", "_gui_release_etag"),
            ("engine_release_etag", "_engine_release_etag"),
        ]:
            val = getattr(self, attr, None)
            if val is not None:
                update[key] = val
        # Cached payload attributes: a None or empty value means "no successful
        # fetch this run"; preserving the previous non-empty cache is the
        # correct behavior on a transient network failure.
        for key, attr in [
            ("gui_cached_release_tag", "_gui_cached_release_tag"),
            ("gui_cached_release_url", "_gui_cached_release_url"),
            ("gui_update_url", "_update_url"),
            ("engine_cached_release_tag", "_engine_cached_release_tag"),
            ("engine_cached_release_url", "_engine_cached_release_url"),
            ("engine_update_url", "_engine_update_url"),
        ]:
            val = getattr(self, attr, None)
            if val:  # truthy: non-empty string
                update[key] = val
        if update:
            self.settings.update(update)

    def _apply_update_result(self, tag, url, notify_on_failure=False):
        kind, display, _link = self._evaluate_update(tag, APP_VERSION)
        status_label = getattr(self, "update_status_label", None)
        ver_label = getattr(self, "gui_version_label", None)
        status_var = getattr(self, "status_var", None)
        link_fg = self._link_fg()
        if status_label is None:
            return
        if kind == "available":
            self._update_url = url or RELEASES_PAGE
            self._render_status_label(
                status_label, ver_label,
                available_text=f"→ v{display} available",
                link_fg=link_fg,
            )
            if status_var is not None:
                status_var.set(
                    f"GUI update available: v{display} - click the version line to open the release page.")
        elif kind == "current":
            self._update_url = None
            self._render_status_label(
                status_label, ver_label,
                current_text="up to date",
                link_fg="",
            )
            if notify_on_failure and status_var is not None:
                status_var.set(f"GUI is up to date (v{APP_VERSION}).")
        else:
            self._update_url = None
            self._render_status_label(
                status_label, ver_label,
                failed_text="check failed",
            )
            if notify_on_failure and status_var is not None:
                status_var.set("Could not determine the latest GUI version.")
            LOG.debug("GUI update check inconclusive (tag=%r)", tag)

    def _link_fg(self):
        try:
            theme_fg = self.style.lookup("TLabel", "foreground")
        except (AttributeError, tk.TclError):
            return "#0b7dda"
        if not theme_fg:
            return "#0b7dda"
        return "#0b7dda" if self._luminance(theme_fg) < 0.5 else "#0b5cd7"

    @staticmethod
    def _render_status_label(status_label, version_label, *,
                              available_text=None, current_text=None,
                              failed_text=None, link_fg=""):
        """Render the GUI update row: a small status label plus an optional
        adjacent version label that also becomes clickable when an update
        is available. Tolerant of dead Tk handles (TclError swallowed)."""
        if available_text is not None:
            try:
                status_label.config(text=available_text, foreground=link_fg, cursor="hand2")
            except tk.TclError:
                try:
                    status_label.config(text=available_text)
                except tk.TclError:
                    pass  # widget gone
            if version_label is not None:
                try:
                    version_label.config(foreground=link_fg, cursor="hand2")
                except tk.TclError:
                    pass
        elif current_text is not None:
            try:
                status_label.config(text=current_text, foreground="", cursor="arrow")
            except tk.TclError:
                try:
                    status_label.config(text=current_text, cursor="arrow")
                except tk.TclError:
                    pass
            if version_label is not None:
                try:
                    version_label.config(foreground="", cursor="arrow")
                except tk.TclError:
                    pass
        elif failed_text is not None:
            try:
                status_label.config(text=failed_text, foreground="gray", cursor="arrow")
            except tk.TclError:
                try:
                    status_label.config(text=failed_text, cursor="arrow")
                except tk.TclError:
                    pass
            if version_label is not None:
                try:
                    version_label.config(foreground="", cursor="arrow")
                except tk.TclError:
                    pass

    def _apply_engine_update_result(self, tag, url, notify_on_failure=False):
        """Apply the result of the engine release check to the engine_version_label.

        The label is updated immediately when an upstream tag is available, even if
        the version probe has not yet succeeded — the user sees the hint as early
        as possible. If the probe has not run yet the label shows the upstream
        version directly (e.g. "v2.1.18 available")."""
        self._engine_release_tag = tag
        self._engine_release_url = url
        # Store the URL so the engine version label can be clicked to open the
        # releases page. Only overwrite with a fresh result; a failed check
        # must not discard a previously cached specific release URL.
        if tag:
            self._engine_update_url = url or ENGINE_RELEASES_PAGE
        label = getattr(self, "engine_version_label", None)
        if label is None:
            return
        try:
            current = getattr(self, "engine_version", "") or ""
            kind, display, _link = self._evaluate_update(tag, current)
            link_fg = self._link_fg()
            if kind == "available":
                text = f"{current} → {display} available" if current else f"v{display} available"
                try:
                    label.config(text=text, foreground=link_fg, cursor="hand2")
                except tk.TclError:
                    label.config(text=text)
            elif kind == "current" and current:
                try:
                    label.config(text=current, foreground="", cursor="arrow")
                except tk.TclError:
                    label.config(text=current, cursor="arrow")
            elif kind == "invalid" and not current and tag and display:
                # Probe has not completed yet but we have a valid upstream tag:
                # show the hint immediately so the user does not see
                # "(probing...)" for several seconds. This is the common
                # startup path when the cached hint is applied before the
                # version probe finishes.
                try:
                    label.config(text=f"v{display} available",
                                 foreground=link_fg, cursor="hand2")
                except tk.TclError:
                    label.config(text=f"v{display} available")
            # else: API failure with a working engine — keep the label as-is.
        except tk.TclError:
            pass

    def manual_update_check(self):
        button = getattr(self, "check_updates_button", None)
        if button is not None:
            button.state(["disabled"])
        self.status_var.set("Checking for updates...")
        threading.Thread(target=lambda: self._update_check_worker(True),
                         daemon=True, name="update-check").start()

    def _open_update_link(self, event=None):
        url = getattr(self, "_update_url", None)
        if url:
            try:
                import webbrowser
                webbrowser.open(url)
            except Exception:
                LOG.debug("Could not open update URL", exc_info=True)

    def _open_engine_update_link(self, event=None):
        url = getattr(self, "_engine_update_url", None)
        if url:
            try:
                import webbrowser
                webbrowser.open(url)
            except Exception:
                LOG.debug("Could not open engine update URL", exc_info=True)

    def toggle_activation(self):
        if self.active_server_info:
            threading.Thread(target=self._activation_worker, args=(None,), daemon=True).start()
        else:
            selected_items = self.tree.selection()
            if not selected_items:
                messagebox.showerror("Error", "Please select one or more servers from the list to activate.")
                return
            server_list = [s for s in self.server_data if s["name"] in selected_items]
            threading.Thread(target=self._activation_worker, args=(server_list,), daemon=True).start()

    def _activation_worker(self, server_list):
        if not self.action_lock.acquire(blocking=False):
            # Never silently swallow a click: another operation (startup
            # restore, config restart) is still in flight.
            self._post_ui(lambda: self.status_var.set(
                "Busy - the current operation has not finished yet."))
            return
        try:
            if self.active_server_info:
                self.deactivate_dns()
            else:
                if server_list: self.activate_dns(server_list)
        finally:
            self.action_lock.release()

    def update_config_and_restart_proxy(self, event=None):
        self.save_settings()
        if self.active_server_info:
            def task():
                if not self.action_lock.acquire(blocking=False):
                    self._post_ui(lambda: self.status_var.set(
                        "Busy - the current operation has not finished yet."))
                    return
                try:
                    self._post_ui(lambda: self.restart_button.config(state=tk.DISABLED, text="Restarting..."))
                    self._post_ui(lambda: self.status_var.set("Restarting proxy..."))
                    current_servers = list(self.active_server_info)
                    self.deactivate_dns()
                    if current_servers:
                        self.activate_dns(current_servers)
                finally:
                    self.action_lock.release()
            threading.Thread(target=task, daemon=True).start()

    def open_bridge_selector(self):
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showinfo("Selection", "Please select a server first."); return

        for server_name in selected_items:
            server_info = self._server_by_name.get(server_name)
            if server_info and server_info.get('proto_type') != "DNSCrypt":
                 messagebox.showwarning("Protocol Error", "Relays can ONLY be assigned to DNSCrypt protocols."); return

        if not self.relay_data:
            messagebox.showerror("Error", "No relay data available."); return

        selector_window = tk.Toplevel(self.root)
        selector_window.title("Select Bridge (Relay)"); selector_window.geometry("500x600")
        selector_window.transient(self.root)
        ttk.Label(selector_window, text=f"Assigning bridge(s) to {len(selected_items)} server(s)", style="Header.TLabel").pack(pady=10)
        
        search_frame = ttk.Frame(selector_window); search_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(search_frame, text="Filter:").pack(side=tk.LEFT)
        search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        list_frame = ttk.Frame(selector_window); list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL)
        relay_listbox = tk.Listbox(list_frame, selectmode=tk.EXTENDED, yscrollcommand=scrollbar.set, font=("Helvetica", 10))
        scrollbar.config(command=relay_listbox.yview); scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        relay_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        all_relay_names = ["(Direct Connection - No Bridge)"] + [r["name"] for r in self.relay_data]
        def update_list(filter_text=""):
            relay_listbox.delete(0, tk.END)
            for name in all_relay_names:
                if filter_text.lower() in name.lower(): relay_listbox.insert(tk.END, name)
        update_list()
        search_var.trace_add("write", lambda name, index, mode, sv=search_var: update_list(sv.get()))

        def confirm_selection():
            selection_indices = relay_listbox.curselection()
            if not selection_indices: return
            selected_relays = [relay_listbox.get(i) for i in selection_indices]
            final_relays = [] if "(Direct Connection - No Bridge)" in selected_relays else selected_relays

            existing_rows = set(self.tree.get_children(''))
            for server_name in selected_items:
                if server_name not in existing_rows:
                    continue  # row disappeared (list refreshed) - skip safely
                if not final_relays:
                    if server_name in self.server_relay_map: del self.server_relay_map[server_name]
                    self.tree.set(server_name, "via", "")
                else:
                    self.server_relay_map[server_name] = final_relays
                    self.tree.set(server_name, "via", ", ".join(final_relays))
            
            self.save_settings()
            selector_window.destroy()
            if self.active_server_info: self.update_config_and_restart_proxy()

        btn_frame = ttk.Frame(selector_window, padding=10); btn_frame.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Button(btn_frame, text="Cancel", command=selector_window.destroy).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Apply Bridge(s)", command=confirm_selection).pack(side=tk.RIGHT)

        # Make the dialog modal: the underlying tree can otherwise be
        # re-filtered while the selector is open, invalidating its rows.
        selector_window.update_idletasks()
        selector_window.grab_set()
        selector_window.focus_set()

    def _clean_server_name(self, name):
        clean = re.sub(r'[^a-zA-Z0-9_]', '', name)
        return clean if clean else "server"

    @staticmethod
    def _toml_literal_escape(value):
        """Escape a string for embedding in a TOML single-quoted literal.

        TOML literal strings cannot contain unescaped backslashes or single
        quotes. The two characters that need escaping are `\\` and `'`; every
        other byte is passed through unchanged. Control characters (U+0000-
        U+0008, U+000A-0x001F) are rejected with a ValueError to surface
        upstream data corruption instead of silently producing invalid TOML.
        """
        if not isinstance(value, str):
            value = str(value)
        if any(ord(c) < 0x20 for c in value):
            raise ValueError(
                f"Refusing to embed control character in TOML literal: {value!r}"
            )
        return value.replace("\\", "\\\\").replace("'", "\\'")

    @staticmethod
    def _coerce_int(raw, default, lo, hi):
        """Clamp user input into a safe integer range."""
        try:
            value = int(str(raw).strip())
        except (TypeError, ValueError):
            value = default
        return max(lo, min(hi, value))

    def _validated_cache_apply(self, var, default, lo, hi, label, event=None):
        raw = var.get().strip()
        value = self._coerce_int(raw, default, lo, hi)
        if str(value) != raw:
            var.set(str(value))
            self.status_var.set(f"{label} was adjusted to {value}.")
        self.update_config_and_restart_proxy()

    def _snapshot_generation_settings(self):
        """Read Tk-bound settings on the main thread; callable from any
        thread. Returns plain values so worker threads never touch the Tcl
        interpreter (which raises 'main thread is not in main loop').

        A 1-second timeout is used (the operation is purely in-process - the
        UI just needs to process a single event). If the main thread is busy
        (e.g. modal dialog or a long-running handler), fall back to the most
        recently saved values in self.settings so the caller is never stuck
        for an unbounded time."""
        done = threading.Event()
        holder = {}

        def grab():
            try:
                holder["value"] = {
                    "config_dir": self.config_dir_var.get().strip(),
                    "cache_size": self.cache_size_var.get(),
                    "cache_min_ttl": self.cache_min_ttl_var.get(),
                    "cache_neg_ttl": self.cache_neg_ttl_var.get(),
                    "block_ipv6": self.block_ipv6_var.get(),
                    "require_dnssec": self.require_dnssec_var.get(),
                    "require_nolog": self.require_nolog_var.get(),
                    "require_nofilter": self.require_nofilter_var.get(),
                }
            except Exception:
                LOG.warning("Could not snapshot generation settings", exc_info=True)
            finally:
                done.set()

        self._post_ui(grab)
        if not done.wait(timeout=1.0):
            # Main thread is unresponsive - use the most recently persisted
            # values. They are always slightly stale relative to the UI but
            # they are consistent with the last user-initiated save.
            LOG.debug("Tk snapshot timed out; using persisted settings")
            return {
                "config_dir": self.settings.get("config_dir", ""),
                "cache_size": self.settings.get("cache_size", "512"),
                "cache_min_ttl": self.settings.get("cache_min_ttl", "60"),
                "cache_neg_ttl": self.settings.get("cache_neg_ttl", "60"),
                "block_ipv6": self.settings.get("block_ipv6", False),
                "require_dnssec": self.settings.get("require_dnssec", False),
                "require_nolog": self.settings.get("require_nolog", False),
                "require_nofilter": self.settings.get("require_nofilter", False),
            }
        return holder.get("value") or {}

    def _generate_config_content(self, server_list, settings=None):
        """Build the dnscrypt-proxy TOML.

        ``settings`` is an optional plain dict of already-read values; when
        omitted, the Tk variables are read directly (main-thread callers and
        tests). Worker threads must always pass a snapshot taken via
        _snapshot_generation_settings()."""
        if settings is None:
            settings = {
                "cache_size": self.cache_size_var.get(),
                "cache_min_ttl": self.cache_min_ttl_var.get(),
                "cache_neg_ttl": self.cache_neg_ttl_var.get(),
                "block_ipv6": self.block_ipv6_var.get(),
                "require_dnssec": self.require_dnssec_var.get(),
                "require_nolog": self.require_nolog_var.get(),
                "require_nofilter": self.require_nofilter_var.get(),
            }
        safe_server_names = []
        name_map = {}

        for s in server_list:
            safe = self._clean_server_name(s['name'])
            base_safe = safe
            counter = 1
            while safe in safe_server_names:
                safe = f"{base_safe}_{counter}"
                counter += 1
            safe_server_names.append(safe)
            name_map[safe] = s

        cache_size = self._coerce_int(settings.get("cache_size"), CACHE_SIZE_DEFAULT, CACHE_SIZE_MIN, CACHE_SIZE_MAX)
        cache_min_ttl = self._coerce_int(settings.get("cache_min_ttl"), CACHE_TTL_DEFAULT, CACHE_TTL_MIN, CACHE_TTL_MAX)
        cache_neg_ttl = self._coerce_int(settings.get("cache_neg_ttl"), CACHE_TTL_DEFAULT, CACHE_TTL_MIN, CACHE_TTL_MAX)

        config_lines = [
            '# Auto-generated by DNSCrypt Client GUI',
            "listen_addresses = ['127.0.0.1:53']",
            f"server_names = {json.dumps(safe_server_names)}",
            '',
            '# --- Global ---',
            f'block_ipv6 = {str(bool(settings.get("block_ipv6"))).lower()}',
            f'require_dnssec = {str(bool(settings.get("require_dnssec"))).lower()}',
            f'require_nolog = {str(bool(settings.get("require_nolog"))).lower()}',
            f'require_nofilter = {str(bool(settings.get("require_nofilter"))).lower()}',
            'ignore_system_dns = true',
            '',
            '# --- Cache ---',
            'cache = true',
            f'cache_size = {cache_size}',
            f'cache_min_ttl = {cache_min_ttl}',
            f'cache_neg_ttl = {cache_neg_ttl}',
            '',
            '# --- Static ---'
        ]
        
        known_relay_stamps = {}
        for r in self.relay_data:
            known_relay_stamps.setdefault(r["name"], r["stamp"])

        relay_safe_names = {}   # original relay name -> unique safe TOML name

        def _unique_relay_safe(original):
            if original in relay_safe_names:
                return relay_safe_names[original]
            base = self._clean_server_name(original)
            candidate, counter = base, 1
            taken = set(relay_safe_names.values()) | set(safe_server_names)
            while candidate in taken:
                candidate = f"{base}_{counter}"
                counter += 1
            relay_safe_names[original] = candidate
            return candidate

        used_relays = set()
        anonymized_routes = []
        
        for safe_name in safe_server_names:
            server_info = name_map[safe_name]
            config_lines.extend([
                f"\n[static.'{safe_name}']",
                f"stamp = '{self._toml_literal_escape(server_info['stamp'])}'"
            ])
            
            relay_list = self.server_relay_map.get(server_info['name'])
            if isinstance(relay_list, str): relay_list = [relay_list] if relay_list else []
            elif not isinstance(relay_list, list):
                # Hand-edited or corrupted settings must not crash config
                # generation - an unusable mapping is simply ignored.
                LOG.warning("Ignoring malformed relay mapping for %r", server_info['name'])
                relay_list = []

            if relay_list and server_info['stamp'].startswith("sdns://AQ"):
                # Drop mappings whose relay has vanished from the upstream
                # list - emitting a route without a matching [static] stamp
                # would make dnscrypt-proxy exit immediately.
                seen_relays = set()
                valid_relays = []
                for r in relay_list:
                    if (isinstance(r, str) and r in known_relay_stamps
                            and r not in seen_relays):
                        seen_relays.add(r)
                        valid_relays.append(r)
                if not valid_relays: continue
                safe_relays = []
                for r_name in valid_relays:
                    safe_relays.append(_unique_relay_safe(r_name))
                    used_relays.add(r_name)
                
                anonymized_routes.append(f"{{ server_name = '{safe_name}', via = {json.dumps(safe_relays)} }}")

        if used_relays:
            config_lines.append('\n# --- Relays ---')
            for original_name in used_relays:
                safe_relay_name = relay_safe_names[original_name]
                config_lines.extend([
                    f"\n[static.'{safe_relay_name}']",
                    f"stamp = '{self._toml_literal_escape(known_relay_stamps[original_name])}'"
                ])

        if anonymized_routes:
            config_lines.append('\n[anonymized_dns]')
            routes_str = ',\n    '.join(anonymized_routes)
            config_lines.append(f"routes = [\n    {routes_str}\n]")
            
        return "\n".join(config_lines)

    def _start_proxy_log_drain(self):
        """Drain the proxy's stderr in a background thread.

        Without this the OS pipe buffer can fill up on a chatty proxy and
        block it mid-run; the last lines are kept for diagnostics."""
        proc = self.proxy_process

        def drain():
            try:
                for line in iter(proc.stderr.readline, ""):
                    if line:
                        self.proxy_log_tail.append(line.rstrip())
            except Exception:
                # A dead drain thread means diagnostics are incomplete;
                # say so instead of reporting a misleading empty log.
                LOG.debug("Proxy stderr drain stopped", exc_info=True)
            finally:
                try:
                    proc.stderr.close()
                except Exception:
                    pass

        self._proxy_log_thread = threading.Thread(
            target=drain, daemon=True, name="proxy-log-drain"
        )
        self._proxy_log_thread.start()

    def _attach_parent_death_guards(self, parent_pid):
        """Make sure the proxy cannot outlive the GUI.

        A force-killed GUI would otherwise leave dnscrypt-proxy orphaned while
        system DNS still points at 127.0.0.1 - an instant, silent outage.
        - Windows: put the proxy in a kill-on-close Job Object owned by this
          process; the kernel kills it whenever our last handle disappears.
        - POSIX: a watchdog thread notices the parent disappearing (getppid
          changes) and shuts the proxy down, restoring system DNS first."""
        if platform.system() == "Windows":
            self._assign_windows_job_object()
        else:
            threading.Thread(
                target=self._posix_parent_watchdog,
                args=(parent_pid,),
                daemon=True,
                name="parent-watchdog",
            ).start()

    def _assign_windows_job_object(self):
        try:
            import ctypes
            from ctypes import wintypes

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_uint64),
                    ("WriteOperationCount", ctypes.c_uint64),
                    ("OtherOperationCount", ctypes.c_uint64),
                    ("ReadTransferCount", ctypes.c_uint64),
                    ("WriteTransferCount", ctypes.c_uint64),
                    ("OtherTransferCount", ctypes.c_uint64),
                ]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            JobObjectExtendedLimitInformation = 9
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

            kernel32 = ctypes.windll.kernel32
            # A previous activation's job is empty by now (its proxy was
            # terminated) - close it so repeated restarts cannot leak handles.
            if self._proxy_job_handle:
                kernel32.CloseHandle(self._proxy_job_handle)
                self._proxy_job_handle = None
            hjob = kernel32.CreateJobObjectW(None, None)
            if not hjob:
                return
            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not kernel32.SetInformationJobObject(
                hjob,
                JobObjectExtendedLimitInformation,
                ctypes.byref(info),
                ctypes.sizeof(info),
            ):
                kernel32.CloseHandle(hjob)
                return
            if kernel32.AssignProcessToJobObject(
                hjob, int(self.proxy_process._handle)
            ):
                self._proxy_job_handle = hjob  # keep alive for process lifetime
            else:
                kernel32.CloseHandle(hjob)
        except Exception:
            LOG.debug("Job Object assignment failed", exc_info=True)

    def _posix_parent_watchdog(self, parent_pid):
        def _stop_proxy():
            proc = self.proxy_process
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass

        while True:
            time.sleep(2)
            if os.getppid() == parent_pid:
                continue
            # Parent is gone - clean up before exiting ourselves.
            try:
                if self.active_server_info:
                    self._revert_after_restore_attempt()
            except Exception:
                # The process is about to exit: this is the last chance to
                # leave a trace of why DNS could not be restored.
                LOG.error("Watchdog cleanup failed before exit", exc_info=True)
            _stop_proxy()
            os._exit(0)

    def _structured_log(self, event, **kwargs):
        """Log a structured event with event name and metadata.

        Structured logs enable log aggregation tools (Sentry, CloudWatch, etc.)
        to query, filter, and correlate events across log streams.

        kwargs values that are not str / int / float / bool are passed through
        repr() so the log line never raises TypeError and remains readable."""
        if kwargs:
            safe = {
                k: (v if isinstance(v, (str, int, float, bool)) else repr(v))
                for k, v in kwargs.items()
            }
            message = f"{event} {safe}"
        else:
            message = event
        LOG.info(message)

    def _log_dns_activation_start(self, server_count):
        self._structured_log("dns_activation_start", server_count=server_count)

    def _log_dns_activation_success(self, server_count, duration_s):
        self._structured_log(
            "dns_activation_success",
            server_count=server_count,
            duration_s=round(duration_s, 3),
        )

    def _log_dns_activation_failure(self, server_count, reason):
        self._structured_log(
            "dns_activation_failure",
            server_count=server_count,
            reason=reason,
        )

    def _log_dns_deactivation_start(self):
        self._structured_log("dns_deactivation_start")

    def _log_dns_deactivation_success(self):
        self._structured_log("dns_deactivation_success")

    def activate_dns(self, server_list):
        def update_ui(key, value):
            if key == 'status':
                self._post_ui(lambda v=value: self.status_var.set(v))
            elif key == 'disable_button':
                # Both buttons disable together so a concurrent Restart click
                # cannot race with a fresh activation. Captured by the same
                # closure so the UI state changes are atomic from the main
                # loop's perspective.
                self._post_ui(lambda: (
                    self.activate_button.config(state=tk.DISABLED),
                    self.restart_button.config(state=tk.DISABLED),
                ))

        update_ui('status', f"Activating {len(server_list)} servers...")
        update_ui('disable_button', True)
        # Log the activation start before any state mutation so log consumers
        # see the intent to activate, even if a later step crashes.
        self._log_dns_activation_start(len(server_list))
        # Claim the active slot immediately so callers see a consistent answer
        # even if a later step fails. The slot is only confirmed in final_success_ui.
        self.active_server_info = []
        _t0 = time.monotonic()
        try:
            settings = self._snapshot_generation_settings()
            config_dir = settings.get("config_dir", "") or self.base_path
            try:
                os.makedirs(config_dir, exist_ok=True)
            except PermissionError as perm_err:
                raise Exception(
                    f"No permission to write the configuration folder:\n{config_dir}\n\n"
                    "On Linux/macOS run the GUI with sudo, or pick a writable folder "
                    "on the Configuration tab."
                ) from perm_err
            config_path = os.path.join(config_dir, CONFIG_FILE)
            with open(config_path, "w", encoding='utf-8') as f: f.write(self._generate_config_content(server_list, settings=settings))
            
            popen_args = self._get_hidden_subprocess_args()
            if 'stdin' in popen_args: del popen_args['stdin']

            # stdout is discarded; stderr is drained by a daemon thread so the
            # OS pipe buffer can never fill up and stall the proxy, while the
            # tail is retained for diagnostics if the process dies.
            self.proxy_log_tail.clear()
            self.proxy_process = subprocess.Popen(
                [self.proxy_executable, "-config", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                **popen_args
            )
            self._start_proxy_log_drain()
            self._attach_parent_death_guards(os.getpid())

            start_time = time.time()
            is_alive = True
            while time.time() - start_time < 2.5:
                if self.proxy_process.poll() is not None:
                    is_alive = False
                    break
                time.sleep(0.1)

            if not is_alive:
                if self._proxy_log_thread:
                    self._proxy_log_thread.join(timeout=1.0)
                err_msg = "\n".join(self.proxy_log_tail) or "Unknown error"
                raise Exception(f"Process exited immediately.\nLog:\n{err_msg}")
                
        except Exception as e:
            update_ui('status', "Error starting proxy.")
            err_text = str(e)
            self._post_ui(lambda t=err_text: messagebox.showerror("Proxy Start Error", t))
            self.stop_proxy_only()
            self._post_ui(lambda: self.activate_button.config(state=tk.NORMAL))
            self._post_ui(lambda: self.restart_button.config(state=tk.NORMAL, text="Restart Proxy"))
            self._log_dns_activation_failure(len(server_list), str(e))
            return

        try:
            self.create_dns_backup()
        except Exception as e:
            err_text = str(e)
            update_ui('status', "Activation aborted - could not back up current DNS settings.")
            self._post_ui(lambda t=err_text: messagebox.showerror(
                "DNS Backup Failed",
                "Activation was aborted because your current system DNS settings "
                f"could not be captured for a safe restore.\n\n{err_text}"))
            self.stop_proxy_only()
            self._post_ui(lambda: self.activate_button.config(state=tk.NORMAL))
            self._post_ui(lambda: self.restart_button.config(state=tk.NORMAL, text="Restart Proxy"))
            self._log_dns_activation_failure(len(server_list), "backup_failed")
            return

        success = False
        for _ in range(5):
             if self.set_system_dns("127.0.0.1"):
                 success = True
                 break
             time.sleep(1)

        if not success:
            update_ui('status', "Failed to set system DNS."); self.stop_proxy_only()
            self._revert_after_restore_attempt()
            self._post_ui(lambda: self.activate_button.config(state=tk.NORMAL))
            self._post_ui(lambda: self.restart_button.config(state=tk.NORMAL, text="Restart Proxy"))
            self._log_dns_activation_failure(len(server_list), "set_system_dns_failed")
            return

        def final_success_ui():
            duration = time.monotonic() - _t0
            self._log_dns_activation_success(len(server_list), duration)
            self.active_server_info = server_list
            self.preferred_servers = [s['name'] for s in server_list]
            self.activate_button.config(text="Deactivate", state=tk.NORMAL)
            self.restart_button.config(state=tk.NORMAL, text="Restart Proxy")
            self.status_indicator.config(text="STATUS: ACTIVE", style="Active.TLabel")
            self.active_server_label.config(text=f"Active: {len(server_list)} servers")
            self.status_var.set(f"Successfully activated {len(server_list)} servers.")
            self.save_settings()
        
        self._post_ui(final_success_ui)

    def deactivate_dns(self):
        self._log_dns_deactivation_start()
        self._post_ui(lambda: self.status_var.set("Deactivating..."))
        self._post_ui(lambda: self.activate_button.config(state=tk.DISABLED))

        # Stop the proxy first so it stops intercepting DNS queries.
        if self.proxy_process:
            self.proxy_process.terminate()
            try:
                self.proxy_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proxy_process.kill()
            self.proxy_process = None

        # Join the drain thread before DNS restore so stderr is fully closed
        # before we touch the system DNS settings.
        drain = getattr(self, "_proxy_log_thread", None)
        if drain:
            drain.join(timeout=1.0)
            self._proxy_log_thread = None

        # Exact restoration of the user's previous DNS configuration; the
        # reset-to-DHCP path is only a last resort when no backup exists.
        self._revert_after_restore_attempt()

        # Now that DNS is restored (or reset), flip the authoritative state.
        # This must happen after DNS restore so that a failed restore can still
        # be retried: callers on worker threads check active_server_info to
        # decide whether retry is needed.
        self.active_server_info = []

        def final_ui_reset():
            self.activate_button.config(text="Activate Selected Server(s)", state=tk.NORMAL if self.tree.selection() else tk.DISABLED)
            self.restart_button.config(state=tk.DISABLED)
            self.status_indicator.config(text="STATUS: INACTIVE", style="Inactive.TLabel")
            self.active_server_label.config(text="No server active.")
            self.status_var.set("Deactivated. System DNS restored.")
            self.save_settings()

        self._post_ui(final_ui_reset)
        # Log while still inside the action_lock critical section, before
        # the lock is released, so activation/deactivation events are atomic
        # with their respective state transitions.
        self._log_dns_deactivation_success()

    def set_system_dns(self, dns_server):
        try:
            if platform.system() == "Windows":
                cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", f"Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' }} | Set-DnsClientServerAddress -ServerAddresses '{dns_server}' -Confirm:$false"]
                self._run_hidden(cmd)
            elif platform.system() == "Darwin":
                for service in self._list_mac_services():
                    result = subprocess.run(
                        ['networksetup', '-setdnsservers', service, dns_server],
                        check=False, capture_output=True,
                        **self._get_hidden_subprocess_args()
                    )
                    if result.returncode != 0:
                        LOG.warning(
                            "networksetup failed for service %r (rc=%d): %s",
                            service, result.returncode, result.stderr.decode(errors="replace")
                        )
                        return False
            elif platform.system() == "Linux":
                with open("/etc/resolv.conf", "w") as f: f.write(f"nameserver {dns_server}\n")
            return True
        except Exception as e:
            LOG.error("Failed to set system DNS to %s: %s", dns_server, e)
            return False

    def revert_system_dns(self):
        """Last-resort reset of system DNS to automatic/DHCP defaults.

        Only used when no exact backup exists; the normal path is
        restore_dns_backup()."""
        try:
            if platform.system() == "Windows":
                 cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Reset-DnsClientServerAddress -Confirm:$false"]
                 self._run_hidden(cmd)
            elif platform.system() == "Darwin":
                for service in self._list_mac_services():
                    result = subprocess.run(
                        ['networksetup', '-setdnsservers', service, 'empty'],
                        check=False, capture_output=True,
                        **self._get_hidden_subprocess_args()
                    )
                    if result.returncode != 0:
                        LOG.warning(
                            "networksetup revert failed for %r (rc=%d): %s",
                            service, result.returncode, result.stderr.decode(errors="replace")
                        )
            elif platform.system() == "Linux":
                if os.path.exists("/etc/resolv.conf"): os.remove("/etc/resolv.conf")
                if os.path.exists('/run/systemd/resolve/stub-resolv.conf'):
                    os.symlink('/run/systemd/resolve/stub-resolv.conf', '/etc/resolv.conf')
        except Exception:
            LOG.warning("revert_system_dns could not complete", exc_info=True)

    def cleanup(self):
        self.is_exiting = True
        # Stop the file watcher so its poll loop exits promptly.
        if getattr(self, "_settings_watcher_stop", None) is not None:
            self._settings_watcher_stop.set()
        if self.active_server_info:
            self.stop_proxy_only()
            self._revert_after_restore_attempt()

    def _revert_after_restore_attempt(self):
        """Restore the exact backup; reset-to-DHCP only as a true last resort.

        A PARTIAL restore (some adapters restored, some failed) keeps
        dns_backup.json on disk so the user can retry. A COMPLETE failure
        due to a corrupt backup file falls through to the DHCP reset so the
        system is never left with DNS pointing at a non-existent proxy."""
        result = self.restore_dns_backup()
        if result is True:
            return
        if result is False:
            # Partial restore failure or corrupt JSON / wrong platform — fall
            # through to DHCP reset only if there is no valid backup on disk.
            if os.path.exists(self.dns_backup_file):
                # A partial failure exists but the backup is still there —
                # caller is responsible for retry. Do NOT fall through.
                return
        # result is None (no file) or result is False with no backup file:
        # no retry possible — fall through to DHCP reset.
        self.revert_system_dns()

    def start_fetch(self):
        threading.Thread(target=self._prepare_and_fetch, daemon=True).start()

    def _prepare_and_fetch(self):
        # Quick UI disable under lock; network I/O happens without lock.
        with self.action_lock:
            self._post_ui(lambda: self.fetch_button.config(state=tk.DISABLED))
            self._post_ui(lambda: self.bridge_button.config(state=tk.DISABLED))
            if not self.server_data:
                self._post_ui(lambda: self.activate_button.config(state=tk.DISABLED))
                self._post_ui(lambda: self.tree.delete(*self.tree.get_children()))
            self._post_ui(lambda: self.status_var.set("Fetching server and relay lists..."))
        # Network I/O without holding the lock.
        self._fetch_and_parse_servers()

    def _parse_markdown_list(self, text):
        data = []
        lines, current_item = text.splitlines(), None
        for line in lines:
            line = line.strip()
            if line.startswith('## '):
                if current_item and 'stamp' in current_item: data.append(current_item)
                current_item = {'name': line[3:].strip(), 'description': '', 'protocols': 'dnscrypt'}
            elif current_item:
                if line.startswith('sdns://'):
                    if 'stamp' not in current_item: current_item['stamp'] = line
                elif line and 'stamp' not in current_item: current_item['description'] += line + '\n'
        if current_item and 'stamp' in current_item: data.append(current_item)
        return data

    def _fetch_and_parse_servers(self):
        try:
            import requests
            session = requests.Session()
            session.headers.update({'User-Agent': f'{APP_NAME}/{APP_VERSION}'})

            # Conditional GETs: unchanged upstream lists return 304 and cost
            # almost nothing, which makes "Refresh" cheap for everyone. The
            # condition is per-URL: only skip when THAT list is cached.
            def conditional_get(url, has_cache):
                headers = {}
                if has_cache and self.fetch_etags.get(url):
                    headers['If-None-Match'] = self.fetch_etags[url]
                return session.get(url, timeout=15, headers=headers)

            resp_res = conditional_get(RESOLVERS_URL, bool(self.server_data))
            if resp_res.status_code == 200:
                self.server_data = self._dedupe_by_name(
                    self._parse_markdown_list(resp_res.text))
                self.fetch_etags[RESOLVERS_URL] = resp_res.headers.get('ETag')
            elif resp_res.status_code != 304:
                resp_res.raise_for_status()

            resp_rel = conditional_get(RELAYS_URL, bool(self.relay_data))
            if resp_rel.status_code == 200:
                self.relay_data = self._dedupe_by_name(
                    self._parse_markdown_list(resp_rel.text))
                self.fetch_etags[RELAYS_URL] = resp_rel.headers.get('ETag')
            elif resp_rel.status_code != 304:
                resp_rel.raise_for_status()
            
            for server in self.server_data:
                stamp = server.get('stamp', '')
                if not stamp:
                    LOG.warning("Server %r has no stamp; skipping proto_type assignment", server.get('name', '(unknown)'))
                    server['proto_type'] = "Other"
                    continue
                server['proto_type'] = "DNSCrypt" if stamp.startswith("sdns://AQ") else ("DoH" if stamp.startswith("sdns://Ag") else "Other")
                desc_lower = server['description'].lower(); props = []
                for prop in ['no-log', 'dnssec', 'no-filter']:
                    keywords = [prop, prop.replace('-', ' ')]; 
                    if prop == 'no-log': keywords.append('no-logging')
                    if prop == 'no-filter': keywords.append('non-filtering')
                    if any(k in desc_lower for k in keywords): server[prop] = '✓'; props.append(prop)
                    else: server[prop] = '✗'
                server['properties'] = ', '.join(props); server['description'] = server['description'].replace('\n', ' ').strip()
            
            self.save_server_cache()
            self._post_ui(self.on_fetch_complete)
        except Exception as e:
            err_text = str(e)

            def handle_error(err_msg):
                if self.server_data:
                    self.status_var.set(f"Fetch failed (using cached list): {err_msg}")
                    self.fetch_button.config(state=tk.NORMAL)
                    if self.tree.selection():
                        self.activate_button.config(state=tk.NORMAL)
                        self.bridge_button.config(state=tk.NORMAL)
                else:
                    self.status_var.set(f"Fetch error: {err_msg}")
                    self.fetch_button.config(state=tk.NORMAL)
            # err_text is bound eagerly: exception variables are deleted when
            # the except block exits, so a plain lambda over `e` would raise
            # NameError inside the Tk callback.
            self._post_ui(lambda m=err_text: handle_error(m))

    def on_fetch_complete(self):
        self._server_by_name = {s["name"]: s for s in self.server_data}
        self._populate_tree(self.server_data)
        self.is_initialized = True
        if not self.active_server_info:
            self.check_auto_activation()

        def final_ui_update():
            self.fetch_button.config(state=tk.NORMAL)
            if self.tree.selection(): self.bridge_button.config(state=tk.NORMAL)
        self._post_ui(final_ui_update)
        
    def check_auto_activation(self):
        if not self.preferred_servers or self._auto_activation_started:
            return
        servers_to_activate = [
            s for s in self.server_data if s["name"] in self.preferred_servers
        ]
        # Only select rows that are actually visible in the tree; the
        # protocol filter may hide some of the preferred servers.
        existing_rows = set(self.tree.get_children(''))
        wanted = [s["name"] for s in servers_to_activate if s["name"] in existing_rows]
        if wanted:
            self.tree.selection_set(wanted)
        if servers_to_activate:
            # check_auto_activation runs both after cache load and after
            # every fetch; without this flag the second invocation would
            # queue a second worker that re-spawns the proxy once the
            # first activation releases the lock.
            self._auto_activation_started = True
            self.status_var.set(f"Automatically reactivating {len(servers_to_activate)} servers...")
            threading.Thread(target=lambda: self._activation_worker_direct(servers_to_activate), daemon=True).start()
        else:
            self.status_var.set("Previous servers not found in current list.")
    
    def _activation_worker_direct(self, servers):
        try:
            with self.action_lock:
                self.activate_dns(servers)
        finally:
            # If activation didn't succeed (no active servers), allow retry.
            if not self.active_server_info:
                self._auto_activation_started = False

    def on_server_select(self, event):
        selected_items = self.tree.selection()
        if not self.active_server_info:
            self.activate_button.config(state=tk.NORMAL if (selected_items and self._proxy_available()) else tk.DISABLED)
        
        can_bridge = bool(selected_items) and all(
            (self._server_by_name.get(name) or {}).get('proto_type') == "DNSCrypt"
            for name in selected_items
        )
        self.bridge_button.config(state=tk.NORMAL if can_bridge else tk.DISABLED)

        focused_id = self.tree.focus()
        if focused_id:
            s = self._server_by_name.get(focused_id)
            if s:
                relay_list = self.server_relay_map.get(s["name"], [])
                if not isinstance(relay_list, list): relay_list = [relay_list] if relay_list else []
                relay_info = ", ".join(relay_list) or "None"
                details = (f"Name: {s['name']}\nProtocol: {s.get('proto_type', 'Unknown')}\nVia Bridge: {relay_info}\n"
                           f"Desc: {s.get('description', '')}\nProps: {s.get('properties', '')}\n\nSTAMP:\n{s.get('stamp', 'unknown')}")
                self.details_text.configure(state='normal'); self.details_text.delete(1.0, tk.END)
                self.details_text.insert(tk.END, details); self.details_text.configure(state='disabled')

def _warn_elevation_required():
    """Show a visible explanation when elevation cannot be obtained."""
    try:
        warn_root = tk.Tk()
        warn_root.withdraw()
        messagebox.showerror(
            "Administrator Privileges Required",
            "This application needs administrator/sudo privileges to manage "
            "your system's DNS settings.\n\nIt will now exit.")
        warn_root.destroy()
    except Exception:
        pass

if __name__ == "__main__":
    if platform.system() == "Windows":
        # Per-monitor-ish DPI awareness: crisp text on high-DPI displays.
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            try:
                import ctypes
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))
    os.chdir(application_path)
    
    if not is_admin():
        try:
            if platform.system() == "Windows":
                import ctypes
                # subprocess.list2cmdline is the platform-correct quoting
                # for CommandLineToArgvW; a hand-rolled " ".join(f'"{a}"')
                # breaks on arguments that already contain quotes.
                params = subprocess.list2cmdline(sys.argv)
                rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
                if rc <= 32:
                    # Elevation was declined or failed (e.g. UAC cancelled).
                    LOG.warning("Elevation declined/failed (ShellExecuteW rc=%s)", rc)
                    _warn_elevation_required()
            else:
                os.execvp('sudo', ['sudo', sys.executable, *sys.argv])
        except Exception:
            LOG.error("Elevation request failed", exc_info=True)
        sys.exit(0)
    
    _instance_lock = acquire_single_instance_lock()
    if _instance_lock is None:
        LOG.warning("Another instance is already running - exiting.")
        try:
            warn_root = tk.Tk(); warn_root.withdraw()
            messagebox.showinfo(
                "Already Running",
                "DNSCrypt Proxy GUI is already running.\n\nCheck the system tray.")
            warn_root.destroy()
        except Exception:
            pass
        sys.exit(0)

    app_root = tk.Tk()
    gui = DNSCryptClientGUI(app_root)
    app_root.mainloop()