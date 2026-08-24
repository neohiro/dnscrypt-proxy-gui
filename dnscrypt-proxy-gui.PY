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
APP_VERSION = "1.0.4"

# dnscrypt-proxy cache tunables. Note: cache_size counts ENTRIES, not bytes.
CACHE_SIZE_DEFAULT, CACHE_SIZE_MIN, CACHE_SIZE_MAX = 512, 64, 1 << 20
CACHE_TTL_DEFAULT, CACHE_TTL_MIN, CACHE_TTL_MAX = 60, 0, 7 * 24 * 3600
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
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        LOG.debug("Admin check failed", exc_info=True)
        return False

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
        mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\" + APP_NAME)
        if mutex and ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
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
        _default_proxy = os.path.join(self.base_path, "dnscrypt-proxy" + (".exe" if is_windows else ""))
        if is_windows:
            _default_cfg_dir = self.base_path
        else:
            _default_cfg_dir = "/etc/dnscrypt-proxy"
        self.proxy_path_var = tk.StringVar(value=self.settings.get("proxy_executable_path", "") or _default_proxy)
        self.config_dir_var = tk.StringVar(value=self.settings.get("config_dir", "") or _default_cfg_dir)

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
        entries = json.loads(output) if output else []
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
        if system == "Windows":
            payload = {"platform": system, "adapters": self._snapshot_dns_windows()}
        elif system == "Darwin":
            payload = {"platform": system, "services": self._snapshot_dns_macos()}
        elif system == "Linux":
            payload = {"platform": system, **self._snapshot_dns_linux()}
        else:
            return
        tmp_path = self.dns_backup_file + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp_path, self.dns_backup_file)

    def restore_dns_backup(self):
        """Restore the exact pre-GUI DNS configuration.

        Returns True when a backup existed and was applied. When no backup
        exists this deliberately does nothing - it must never guess."""
        try:
            with open(self.dns_backup_file, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except FileNotFoundError:
            return False
        except Exception:
            return False  # corrupt backup: caller decides on fallback policy
        system = platform.system()
        if payload.get("platform") != system:
            return False
        if system == "Windows":
            failures = self._restore_dns_windows(payload.get("adapters", {}))
        elif system == "Darwin":
            failures = self._restore_dns_macos(payload.get("services", {}))
        elif system == "Linux":
            failures = self._restore_dns_linux(payload)
        else:
            failures = []
        try:
            os.remove(self.dns_backup_file)
        except OSError:
            pass
        return not failures

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

    def manual_restore_dns(self):
        """Safety hatch: put the system DNS back the way the user had it."""
        if not self.action_lock.acquire(blocking=False):
            self.status_var.set("Busy - please wait for the current operation to finish.")
            return
        self.action_lock.release()
        threading.Thread(target=self._manual_restore_worker, daemon=True).start()

    def _manual_restore_worker(self):
        with self.action_lock:
            if self.active_server_info:
                self.deactivate_dns()
                return
            if os.path.exists(self.dns_backup_file):
                restored = self.restore_dns_backup()
                message = ("System DNS restored to your previous settings."
                           if restored else
                           "Restore failed - see log for details.")
            else:
                message = "No saved DNS state to restore (nothing was changed)."
            self.root.after(0, lambda m=message: self.status_var.set(m))

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

    def check_proxy_executable(self):
        candidate = self.proxy_path_var.get().strip()
        if not candidate:
            exe_name = "dnscrypt-proxy" + (".exe" if platform.system() == "Windows" else "")
            local_candidate = os.path.join(self.base_path, exe_name)
            candidate = local_candidate if os.path.exists(local_candidate) else exe_name
        self.proxy_executable = candidate
        if self._proxy_available():
            self.activate_button.config(state=tk.NORMAL)
        else:
            messagebox.showwarning(
                "Executable Not Found",
                f"'{candidate}' was not found.\n\n"
                "Place dnscrypt-proxy next to the GUI, install it on your PATH, "
                "or set the exact location on the Configuration tab.",
                parent=self.root,
            )
            self.activate_button.config(state=tk.DISABLED)

    def _proxy_available(self):
        """True when the configured proxy can actually be launched.

        The candidate may be a bare name that only resolves via PATH, so a
        plain os.path.exists() check is not sufficient here."""
        candidate = getattr(self, 'proxy_executable', '')
        return bool(candidate) and (
            os.path.isfile(candidate) or shutil.which(candidate) is not None
        )

    def setup_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        activation_frame = ttk.Frame(main_frame, padding=5, relief=tk.RIDGE)
        activation_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.activate_button = ttk.Button(activation_frame, text="Activate Selected Server(s)", command=self.toggle_activation, state=tk.DISABLED)
        self.activate_button.pack(side=tk.RIGHT, padx=10, pady=5)
        
        startup_check = ttk.Checkbutton(activation_frame, text="Run at system startup", variable=self.startup_var, command=self.toggle_startup)
        startup_check.pack(side=tk.RIGHT, padx=5)

        minimized_check = ttk.Checkbutton(activation_frame, text="Start minimized to tray", variable=self.start_minimized_var, command=self.save_settings)
        minimized_check.pack(side=tk.RIGHT, padx=10)

        self.status_indicator = ttk.Label(activation_frame, text="STATUS: INACTIVE", style="Inactive.TLabel")
        self.status_indicator.pack(side=tk.LEFT, padx=10)

        self.restore_dns_button = ttk.Button(activation_frame, text="Restore DNS", command=self.manual_restore_dns)
        self.restore_dns_button.pack(side=tk.LEFT, padx=(0, 10))

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

        def _luminance(color):
            color = str(color).lstrip('#')
            if len(color) == 3:
                color = ''.join(c * 2 for c in color)
            try:
                r, g, b = (int(color[i:i + 2], 16) for i in (0, 2, 4))
            except ValueError:
                return 1.0
            return (0.299 * r + 0.587 * g + 0.114 * b) / 255

        if _luminance(theme_bg) >= 0.5:
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

        ttk.Label(parent, text="Changes are applied immediately if the service is active.", style="Status.TLabel").pack(pady=20)
    
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
            "config_dir": self.config_dir_var.get()
        }
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings_to_save, f, indent=4)
        except Exception: pass 

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
                self.server_data = data.get("servers", [])
                self.relay_data = data.get("relays", [])
                self.fetch_etags = data.get("etags", {})
                self._server_by_name = {s["name"]: s for s in self.server_data}
                self.server_cache_ts = data.get("timestamp")
                return True
        except Exception:
            LOG.debug("Could not load server cache", exc_info=True)
            return False

    def setup_tray_and_close_protocol(self):
        self.root.protocol('WM_DELETE_WINDOW', self.on_close_window)

    def on_close_window(self):
        if not TRAY_AVAILABLE:
            # No tray icon exists, so closing must not silently strand the
            # app as an unminimizable ghost - ask the user explicitly.
            if messagebox.askyesno(
                    "Exit DNSCrypt Client?",
                    "The system tray icon is unavailable.\n"
                    "Closing this window will EXIT the application\n"
                    "(and deactivate the proxy). Continue?"):
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
        if not TRAY_AVAILABLE:
            # No system-tray backend available - minimising keeps the app
            # reachable instead of hiding it with no way back.
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
            except Exception as e:
                print(f"Tray error: {e}")
                LOG.error("Tray icon crashed", exc_info=True)
                self.quit_app()

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

    def get_startup_path_and_command(self):
        script_path = os.path.abspath(sys.argv[0])
        command = f'"{sys.executable}" "{script_path}"'
        return script_path, command

    def toggle_startup(self):
        if self.startup_var.get(): self.add_to_startup()
        else: self.remove_from_startup()

    def add_to_startup(self):
        system = platform.system()
        _, command = self.get_startup_path_and_command()
        try:
            if system == "Windows":
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, command)
            elif system == "Linux":
                autostart_path = os.path.expanduser("~/.config/autostart")
                os.makedirs(autostart_path, exist_ok=True)
                desktop_file_path = os.path.join(autostart_path, f"{APP_NAME}.desktop")
                with open(desktop_file_path, "w") as f:
                    f.write(f"[Desktop Entry]\nType=Application\nExec={command}\nX-GNOME-Autostart-enabled=true\nName={APP_NAME}\n")
            elif system == "Darwin":
                agent_path = os.path.expanduser(f"~/Library/LaunchAgents/com.{APP_NAME}.plist")
                plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.{APP_NAME}</string>
<key>ProgramArguments</key><array><string>{sys.executable}</string><string>{os.path.abspath(sys.argv[0])}</string></array>
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
            values = (server["name"], server.get('proto_type', '?'), ", ".join(relays), server["no-log"], server["dnssec"], server["no-filter"])
            
            tag = 'oddrow' if i % 2 != 0 else 'evenrow'
            self.tree.insert("", tk.END, values=values, iid=server["name"], tags=(tag,))
            
        self.status_var.set(f"Showing {len(filtered_list)} servers ({len(self.server_data)} total) and {len(self.relay_data)} relays.")
        self.apply_current_sorts()

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
            self.root.after(0, lambda: self.status_var.set(
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
            if not self.action_lock.acquire(blocking=False): return
            def task():
                try:
                    self.root.after(0, lambda: self.status_var.set("Configuration changed. Restarting proxy..."))
                    current_servers = self.active_server_info
                    self.deactivate_dns()
                    if not self.active_server_info: self.activate_dns(current_servers)
                finally: self.action_lock.release()
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

    def _generate_config_content(self, server_list):
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

        cache_size = self._coerce_int(self.cache_size_var.get(), CACHE_SIZE_DEFAULT, CACHE_SIZE_MIN, CACHE_SIZE_MAX)
        cache_min_ttl = self._coerce_int(self.cache_min_ttl_var.get(), CACHE_TTL_DEFAULT, CACHE_TTL_MIN, CACHE_TTL_MAX)
        cache_neg_ttl = self._coerce_int(self.cache_neg_ttl_var.get(), CACHE_TTL_DEFAULT, CACHE_TTL_MIN, CACHE_TTL_MAX)

        config_lines = [
            '# Auto-generated by DNSCrypt Client GUI', 
            "listen_addresses = ['127.0.0.1:53']",
            f"server_names = {json.dumps(safe_server_names)}", 
            '', 
            '# --- Global ---',
            f'block_ipv6 = {str(self.block_ipv6_var.get()).lower()}',
            f'require_dnssec = {str(self.require_dnssec_var.get()).lower()}',
            f'require_nolog = {str(self.require_nolog_var.get()).lower()}',
            f'require_nofilter = {str(self.require_nofilter_var.get()).lower()}', 
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
            config_lines.extend([f"\n[static.'{safe_name}']", f"stamp = '{server_info['stamp']}'"])
            
            relay_list = self.server_relay_map.get(server_info['name'])
            if isinstance(relay_list, str): relay_list = [relay_list] if relay_list else []
            
            if relay_list and server_info['stamp'].startswith("sdns://AQ"):
                # Drop mappings whose relay has vanished from the upstream
                # list - emitting a route without a matching [static] stamp
                # would make dnscrypt-proxy exit immediately.
                valid_relays = [r for r in relay_list if r in known_relay_stamps]
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
                    f"stamp = '{known_relay_stamps[original_name]}'"
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
                pass
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
                    if not self.restore_dns_backup():
                        self.revert_system_dns()
            except Exception:
                pass
            _stop_proxy()
            os._exit(0)

    def activate_dns(self, server_list):
        def update_ui(key, value):
            self.root.after(0, lambda: self.status_var.set(value) if key == 'status' else None)
            if key == 'disable_button': self.root.after(0, lambda: self.activate_button.config(state=tk.DISABLED))

        update_ui('status', f"Activating {len(server_list)} servers...")
        update_ui('disable_button', True)

        try:
            config_dir = self.config_dir_var.get().strip() or self.base_path
            try:
                os.makedirs(config_dir, exist_ok=True)
            except PermissionError as perm_err:
                raise Exception(
                    f"No permission to write the configuration folder:\n{config_dir}\n\n"
                    "On Linux/macOS run the GUI with sudo, or pick a writable folder "
                    "on the Configuration tab."
                ) from perm_err
            config_path = os.path.join(config_dir, CONFIG_FILE)
            with open(config_path, "w", encoding='utf-8') as f: f.write(self._generate_config_content(server_list))
            
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
            self.root.after(0, lambda t=err_text: messagebox.showerror("Proxy Start Error", t))
            self.stop_proxy_only()
            self.root.after(0, lambda: self.activate_button.config(state=tk.NORMAL))
            return

        try:
            self.create_dns_backup()
        except Exception as e:
            err_text = str(e)
            update_ui('status', "Activation aborted - could not back up current DNS settings.")
            self.root.after(0, lambda t=err_text: messagebox.showerror(
                "DNS Backup Failed",
                "Activation was aborted because your current system DNS settings "
                f"could not be captured for a safe restore.\n\n{err_text}"))
            self.stop_proxy_only()
            self.root.after(0, lambda: self.activate_button.config(state=tk.NORMAL))
            return

        success = False
        for _ in range(5):
             if self.set_system_dns("127.0.0.1"):
                 success = True
                 break
             time.sleep(1)

        if not success:
             update_ui('status', "Failed to set system DNS."); self.stop_proxy_only()
             self.restore_dns_backup()
             self.root.after(0, lambda: self.activate_button.config(state=tk.NORMAL))
             return
        
        def final_success_ui():
            self.active_server_info = server_list
            self.preferred_servers = [s['name'] for s in server_list]
            self.activate_button.config(text="Deactivate", state=tk.NORMAL)
            self.status_indicator.config(text="STATUS: ACTIVE", style="Active.TLabel")
            self.active_server_label.config(text=f"Active: {len(server_list)} servers")
            self.status_var.set(f"Successfully activated {len(server_list)} servers.")
            self.save_settings()
        
        self.root.after(0, final_success_ui)

    def deactivate_dns(self):
        self.root.after(0, lambda: self.status_var.set("Deactivating..."))
        self.root.after(0, lambda: self.activate_button.config(state=tk.DISABLED))

        if self.proxy_process:
            self.proxy_process.terminate()
            try:
                self.proxy_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proxy_process.kill()
            self.proxy_process = None

        # Exact restoration of the user's previous DNS configuration; the
        # reset-to-DHCP path is only a last resort when no backup exists.
        if not self.restore_dns_backup():
            self.revert_system_dns()
        
        def final_ui_reset():
            self.active_server_info = []
            self.activate_button.config(text="Activate Selected Server(s)", state=tk.NORMAL if self.tree.selection() else tk.DISABLED)
            self.status_indicator.config(text="STATUS: INACTIVE", style="Inactive.TLabel")
            self.active_server_label.config(text="No server active.")
            self.status_var.set("Deactivated. System DNS restored.")
            self.save_settings()
        
        self.root.after(0, final_ui_reset)

    def set_system_dns(self, dns_server):
        try:
            if platform.system() == "Windows":
                cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", f"Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' }} | Set-DnsClientServerAddress -ServerAddresses '{dns_server}' -Confirm:$false"]
                self._run_hidden(cmd)
            elif platform.system() == "Darwin":
                for service in self._list_mac_services():
                    subprocess.run(['networksetup', '-setdnsservers', service, dns_server], check=False, capture_output=True, **self._get_hidden_subprocess_args())
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
                    subprocess.run(['networksetup', '-setdnsservers', service, 'empty'], check=False, capture_output=True, **self._get_hidden_subprocess_args())
            elif platform.system() == "Linux":
                if os.path.exists("/etc/resolv.conf"): os.remove("/etc/resolv.conf")
                if os.path.exists('/run/systemd/resolve/stub-resolv.conf'):
                    os.symlink('/run/systemd/resolve/stub-resolv.conf', '/etc/resolv.conf')
        except Exception:
            LOG.warning("revert_system_dns could not complete", exc_info=True)

    def cleanup(self):
        self.is_exiting = True
        if self.active_server_info:
            self.stop_proxy_only()
            if not self.restore_dns_backup():
                self.revert_system_dns()

    def start_fetch(self):
        threading.Thread(target=self._prepare_and_fetch, daemon=True).start()

    def _prepare_and_fetch(self):
        with self.action_lock:
            self.root.after(0, lambda: self.fetch_button.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.bridge_button.config(state=tk.DISABLED))
            
            if not self.server_data:
                self.root.after(0, lambda: self.activate_button.config(state=tk.DISABLED))
                self.root.after(0, lambda: self.tree.delete(*self.tree.get_children()))
                
            self.root.after(0, lambda: self.status_var.set("Fetching server and relay lists..."))
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
                self.server_data = self._parse_markdown_list(resp_res.text)
                self.fetch_etags[RESOLVERS_URL] = resp_res.headers.get('ETag')
            elif resp_res.status_code != 304:
                resp_res.raise_for_status()

            resp_rel = conditional_get(RELAYS_URL, bool(self.relay_data))
            if resp_rel.status_code == 200:
                self.relay_data = self._parse_markdown_list(resp_rel.text)
                self.fetch_etags[RELAYS_URL] = resp_rel.headers.get('ETag')
            elif resp_rel.status_code != 304:
                resp_rel.raise_for_status()
            
            for server in self.server_data:
                server['proto_type'] = "DNSCrypt" if server['stamp'].startswith("sdns://AQ") else ("DoH" if server['stamp'].startswith("sdns://Ag") else "Other")
                desc_lower = server['description'].lower(); props = []
                for prop in ['no-log', 'dnssec', 'no-filter']:
                    keywords = [prop, prop.replace('-', ' ')]; 
                    if prop == 'no-log': keywords.append('no-logging')
                    if prop == 'no-filter': keywords.append('non-filtering')
                    if any(k in desc_lower for k in keywords): server[prop] = '✓'; props.append(prop)
                    else: server[prop] = '✗'
                server['properties'] = ', '.join(props); server['description'] = server['description'].replace('\n', ' ').strip()
            
            self.save_server_cache()
            self.root.after(0, self.on_fetch_complete)
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
            self.root.after(0, lambda m=err_text: handle_error(m))

    def on_fetch_complete(self):
        self._server_by_name = {s["name"]: s for s in self.server_data}
        self._populate_tree(self.server_data)
        self.is_initialized = True
        if not self.active_server_info:
            self.check_auto_activation()

        def final_ui_update():
            self.fetch_button.config(state=tk.NORMAL)
            if self.tree.selection(): self.bridge_button.config(state=tk.NORMAL)
        self.root.after(0, final_ui_update)
        
    def check_auto_activation(self):
        if not self.preferred_servers: return
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
            self.status_var.set(f"Automatically reactivating {len(servers_to_activate)} servers...")
            threading.Thread(target=lambda: self._activation_worker_direct(servers_to_activate), daemon=True).start()
        else:
            self.status_var.set("Previous servers not found in current list.")
    
    def _activation_worker_direct(self, servers):
        with self.action_lock:
             self.activate_dns(servers)

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
                relay_info = ", ".join(relay_list if isinstance(relay_list, list) else [relay_list]) or "None"
                details = (f"Name: {s['name']}\nProtocol: {s.get('proto_type', 'Unknown')}\nVia Bridge: {relay_info}\n"
                           f"Desc: {s['description']}\nProps: {s['properties']}\n\nSTAMP:\n{s['stamp']}")
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
                params = " ".join([f'"{arg}"' for arg in sys.argv])
                rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
                if rc <= 32:
                    # Elevation was declined or failed (e.g. UAC cancelled).
                    LOG.warning("Elevation declined/failed (ShellExecuteW rc=%s)", rc)
                    _warn_elevation_required()
            else:
                os.execvp('sudo', ['sudo', sys.executable] + sys.argv)
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