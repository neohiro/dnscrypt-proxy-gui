import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import threading
import os
import sys
import subprocess
import platform
import atexit
import time
import json
import re

# --- New Imports for Tray Icon and Startup ---
try:
    from pystray import MenuItem as item, Icon as icon
    from PIL import Image, ImageTk
except ImportError:
    try:
        # Fallback if imports fail, though in a real app better to handle gracefully
        # pass to allow GUI to at least try to load if libs are missing (but tray won't work)
        pass
    except:
        pass

if platform.system() == "Windows":
    import winreg

# --- Constants ---
APP_NAME = "DNSCryptClientGUI"
RESOLVERS_URL = "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md"
RELAYS_URL = "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md"
CONFIG_FILE = "dnscrypt-proxy.toml"
SETTINGS_FILE_NAME = "settings.json"
CACHE_FILE_NAME = "server_cache.json" 
ICON_FILE = "icon.ico"

# --- Console Suppression Helper ---
# Modified: We only suppress if frozen, otherwise we want to see errors in IDE
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
        return False

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
        self.active_server_info = []
        self.proxy_process = None
        
        self.action_lock = threading.Lock() 
        self.tray_icon = None 
        self.tray_thread = None 
        self.tray_lock = threading.Lock()
        self.app_icon_image = None
        self.icon_path = None
        
        # --- CRITICAL FLAGS ---
        self.is_exiting = False 
        self.is_initialized = False 

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

        # Determine Absolute Paths
        if getattr(sys, 'frozen', False):
            self.base_path = os.path.dirname(sys.executable)
        else:
            self.base_path = os.path.dirname(os.path.abspath(__file__))
        
        self.settings_file = os.path.join(self.base_path, SETTINGS_FILE_NAME)
        self.cache_file = os.path.join(self.base_path, CACHE_FILE_NAME)

        self.settings = self.load_settings() 
        
        # Load preferred servers
        self.preferred_servers = self.settings.get("last_active_servers", [])
        
        # Load UI State
        self.protocol_filter_var.set(self.settings.get("ui_filter_protocol", "All Protocols"))
        self.start_minimized_var.set(self.settings.get("ui_start_minimized", False))
        
        # --- Multi-Column Sort Persistence ---
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

        # --- FIX: Clean State on Init ---
        self.revert_system_dns()

        atexit.register(self.cleanup)
        
        self.load_app_icon()
        self.setup_widgets()
        self.setup_tray_and_close_protocol()
        
        self.check_proxy_executable()
        self.check_startup_status()

        # --- CACHE LOGIC ---
        self.load_server_cache()
        if self.server_data:
            self.status_var.set(f"Loaded {len(self.server_data)} servers from local cache.")
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
                    self.app_icon_image = Image.open(self.icon_path)
                    break
                except Exception: pass

    def check_proxy_executable(self):
        self.proxy_executable = "dnscrypt-proxy"
        if platform.system() == "Windows": self.proxy_executable += ".exe"
        abs_proxy = os.path.join(self.base_path, self.proxy_executable)
        if os.path.exists(abs_proxy):
            self.proxy_executable = abs_proxy
        elif not os.path.exists(self.proxy_executable):
            messagebox.showwarning("Executable Not Found", f"'{self.proxy_executable}' not found in\n{self.base_path}\n\nPlease place dnscrypt-proxy.exe in this folder.")
            self.activate_button.config(state=tk.DISABLED)

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
        
        self.tree.heading("name", text="Server Name", command=lambda: self.on_header_click("name"))
        self.tree.column("name", width=220, stretch=tk.YES)
        self.tree.heading("type", text="Protocol", command=lambda: self.on_header_click("type"))
        self.tree.column("type", width=80, anchor=tk.CENTER)
        self.tree.heading("via", text="Via Bridge(s)", command=lambda: self.on_header_click("via"))
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
        ttk.Label(size_frame, text="Cache size (bytes):", width=25).pack(side=tk.LEFT)
        size_entry = ttk.Entry(size_frame, textvariable=self.cache_size_var, width=15)
        size_entry.pack(side=tk.LEFT, padx=5)
        size_entry.bind("<FocusOut>", self.update_config_and_restart_proxy)

        min_ttl_frame = ttk.Frame(cache_frame); min_ttl_frame.pack(fill=tk.X, pady=3)
        ttk.Label(min_ttl_frame, text="Cache min TTL (seconds):", width=25).pack(side=tk.LEFT)
        min_ttl_entry = ttk.Entry(min_ttl_frame, textvariable=self.cache_min_ttl_var, width=15)
        min_ttl_entry.pack(side=tk.LEFT, padx=5)
        min_ttl_entry.bind("<FocusOut>", self.update_config_and_restart_proxy)

        neg_ttl_frame = ttk.Frame(cache_frame); neg_ttl_frame.pack(fill=tk.X, pady=3)
        ttk.Label(neg_ttl_frame, text="Cache negative TTL (seconds):", width=25).pack(side=tk.LEFT)
        neg_ttl_entry = ttk.Entry(neg_ttl_frame, textvariable=self.cache_neg_ttl_var, width=15)
        neg_ttl_entry.pack(side=tk.LEFT, padx=5)
        neg_ttl_entry.bind("<FocusOut>", self.update_config_and_restart_proxy)

        ttk.Label(parent, text="Changes are applied immediately if the service is active.", style="Status.TLabel").pack(pady=20)
    
    def save_settings(self):
        if self.is_exiting or not self.is_initialized:
            return
        
        servers_to_save = [s['name'] for s in self.active_server_info]
        if not servers_to_save:
             servers_to_save = self.preferred_servers

        settings_to_save = {
            "was_active": bool(self.active_server_info),
            "last_active_servers": servers_to_save,
            "server_relay_map": self.server_relay_map,
            "ui_filter_protocol": self.protocol_filter_var.get(),
            "ui_start_minimized": self.start_minimized_var.get(),
            "ui_sort_stack": self.sort_stack,
            "ui_sort_dirs": self.sort_dirs,
            "block_ipv6": self.block_ipv6_var.get(),
            "require_dnssec": self.require_dnssec_var.get(),
            "require_nolog": self.require_nolog_var.get(),
            "require_nofilter": self.require_nofilter_var.get(),
            "cache_size": self.cache_size_var.get(),
            "cache_neg_ttl": self.cache_neg_ttl_var.get(),
            "cache_min_ttl": self.cache_min_ttl_var.get()
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
            "timestamp": time.time()
        }
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f)
        except Exception as e:
            print(f"Failed to save cache: {e}")

    def load_server_cache(self):
        try:
            if not os.path.exists(self.cache_file): return False
            with open(self.cache_file, 'r') as f:
                data = json.load(f)
                self.server_data = data.get("servers", [])
                self.relay_data = data.get("relays", [])
                return True
        except Exception:
            return False

    def setup_tray_and_close_protocol(self):
        self.root.protocol('WM_DELETE_WINDOW', self.hide_window)

    def hide_window(self):
        self.root.withdraw()
        def start_icon_thread():
            try:
                image = self.app_icon_image if self.app_icon_image else Image.new('RGB', (64, 64), 'green')
                menu = (item('Show', self.show_window, default=True), item('Exit', self.quit_app))
                with self.tray_lock: self.tray_icon = icon(APP_NAME, image, "DNSCrypt Client", menu)
                self.tray_icon.run() 
                with self.tray_lock: self.tray_icon = None
            except Exception as e:
                # If tray fails, just destroy app
                print(f"Tray error: {e}")
                self.quit_app()

        with self.tray_lock:
            if not (self.tray_thread and self.tray_thread.is_alive()):
                self.tray_thread = threading.Thread(target=start_icon_thread, daemon=True)
                self.tray_thread.start()

    def show_window(self):
        with self.tray_lock:
            if self.tray_icon: self.tray_icon.stop()
        self.root.deiconify(); self.root.lift(); self.root.attributes('-topmost', 1); self.root.attributes('-topmost', 0)

    def quit_app(self):
        with self.tray_lock:
            if self.tray_icon: self.tray_icon.stop()
        self.root.destroy()

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
        except: is_startup = False
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
        for index, (iid, _) in enumerate(data_rows): self.tree.move(iid, '', index)
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
        for server in filtered_list:
            relays = self.server_relay_map.get(server["name"], [])
            if isinstance(relays, str): relays = [relays] if relays else []
            values = (server["name"], server.get('proto_type', '?'), ", ".join(relays), server["no-log"], server["dnssec"], server["no-filter"])
            self.tree.insert("", tk.END, values=values, iid=server["name"])
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
        if not self.action_lock.acquire(blocking=False): return
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
            server_info = next((s for s in self.server_data if s["name"] == server_name), None)
            if server_info and server_info.get('proto_type') != "DNSCrypt":
                 messagebox.showwarning("Protocol Error", "Relays can ONLY be assigned to DNSCrypt protocols."); return

        if not self.relay_data:
            messagebox.showerror("Error", "No relay data available."); return

        selector_window = tk.Toplevel(self.root)
        selector_window.title("Select Bridge (Relay)"); selector_window.geometry("500x600")
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
            
            for server_name in selected_items:
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

    def _clean_server_name(self, name):
        """Sanitizes server names to be safe for TOML keys."""
        # Remove anything that isn't alphanumeric or underscore
        clean = re.sub(r'[^a-zA-Z0-9_]', '', name)
        return clean if clean else "server"

    def _generate_config_content(self, server_list):
        # Generate internal safe names to prevent TOML syntax errors with spaces/special chars
        safe_server_names = []
        name_map = {} # Maps safe_name -> server_info

        for s in server_list:
            safe = self._clean_server_name(s['name'])
            # Ensure unique safe names
            base_safe = safe
            counter = 1
            while safe in safe_server_names:
                safe = f"{base_safe}_{counter}"
                counter += 1
            safe_server_names.append(safe)
            name_map[safe] = s

        try: cache_size = int(self.cache_size_var.get())
        except: cache_size = 512
        try: cache_min_ttl = int(self.cache_min_ttl_var.get())
        except: cache_min_ttl = 60
        try: cache_neg_ttl = int(self.cache_neg_ttl_var.get())
        except: cache_neg_ttl = 60

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
            "fallback_resolver = '9.9.9.9:53'", # CRITICAL FIX: Fallback prevents total lockout
            '',
            '# --- Cache ---', 
            'cache = true', 
            f'cache_size = {cache_size}',
            f'cache_min_ttl = {cache_min_ttl}', 
            f'cache_neg_ttl = {cache_neg_ttl}', 
            '', 
            '# --- Static ---'
        ]
        
        used_relays = set()
        anonymized_routes = []
        
        # Write static entries using SAFE names
        for safe_name in safe_server_names:
            server_info = name_map[safe_name]
            config_lines.extend([f"\n[static.'{safe_name}']", f"stamp = '{server_info['stamp']}'"])
            
            relay_list = self.server_relay_map.get(server_info['name'])
            if isinstance(relay_list, str): relay_list = [relay_list] if relay_list else []
            
            if relay_list and server_info['stamp'].startswith("sdns://AQ"):
                # Clean relay names too for the route, but relay static definitions usually come from the relay list
                # Relays in the route must match the static relay names we define below
                safe_relays = []
                for r_name in relay_list:
                    r_clean = self._clean_server_name(r_name)
                    safe_relays.append(r_clean)
                    used_relays.add((r_name, r_clean)) # Keep track of original vs clean
                
                # Routes use safe names
                anonymized_routes.append(f"{{ server_name = '{safe_name}', via = {json.dumps(safe_relays)} }}")

        if used_relays:
            config_lines.append('\n# --- Relays ---')
            for original_name, safe_relay_name in used_relays:
                relay_info = next((r for r in self.relay_data if r["name"] == original_name), None)
                if relay_info: 
                    config_lines.extend([f"\n[static.'{safe_relay_name}']", f"stamp = '{relay_info['stamp']}'"])

        if anonymized_routes:
            config_lines.append('\n[anonymized_dns]')
            config_lines.append(f"routes = [\n    {',\n    '.join(anonymized_routes)}\n]")
            
        return "\n".join(config_lines)

    def activate_dns(self, server_list):
        def update_ui(key, value):
            self.root.after(0, lambda: self.status_var.set(value) if key == 'status' else None)
            if key == 'disable_button': self.root.after(0, lambda: self.activate_button.config(state=tk.DISABLED))

        update_ui('status', f"Activating {len(server_list)} servers...")
        update_ui('disable_button', True)

        try:
            # Generate config using absolute path
            config_path = os.path.join(self.base_path, CONFIG_FILE)
            with open(config_path, "w", encoding='utf-8') as f: f.write(self._generate_config_content(server_list))
            
            # --- FIX: Better process handling & Error Capture ---
            popen_args = self._get_hidden_subprocess_args()
            # We MUST remove capturing flags if we want to read stdout/stderr specifically, 
            # but _get_hidden_subprocess_args sets them up for hidden execution. 
            # To debug, we pipe them.
            
            # Remove DEVNULL from stdin so we can pipe, keep creation flags
            if 'stdin' in popen_args: del popen_args['stdin']
            
            self.proxy_process = subprocess.Popen(
                [self.proxy_executable, "-config", config_path], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                stdin=subprocess.DEVNULL,
                **popen_args
            )
            
            # Wait a moment and check if it died immediately
            start_time = time.time()
            is_alive = True
            while time.time() - start_time < 2.5:
                if self.proxy_process.poll() is not None:
                    is_alive = False
                    break
                time.sleep(0.1)

            if not is_alive:
                # Capture Error
                _, err = self.proxy_process.communicate()
                err_msg = err.decode('utf-8', errors='ignore') if err else "Unknown error"
                raise Exception(f"Process exited immediately.\nLog:\n{err_msg}")
                
        except Exception as e:
            update_ui('status', "Error starting proxy.")
            self.root.after(0, lambda: messagebox.showerror("Proxy Start Error", str(e)))
            self.cleanup()
            # Re-enable button
            self.root.after(0, lambda: self.activate_button.config(state=tk.NORMAL))
            return

        # --- Set System DNS with Retry ---
        success = False
        for attempt in range(5):
             if self.set_system_dns("127.0.0.1"):
                 success = True
                 break
             time.sleep(1) 

        if not success:
             update_ui('status', "Failed to set system DNS."); self.cleanup()
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
        run_args = self._get_hidden_subprocess_args()
        try:
            if platform.system() == "Windows":
                # PowerShell command to set DNS on the Up adapter
                cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", f"Get-NetAdapter | Where-Object {{ $_.Status -eq 'Up' }} | Set-DnsClientServerAddress -ServerAddresses '{dns_server}' -Confirm:$false"]
                subprocess.run(cmd, check=True, capture_output=True, **run_args)
            elif platform.system() == "Darwin":
                result = subprocess.run(['networksetup', '-listallnetworkservices'], check=True, capture_output=True, **run_args)
                for service in result.stdout.splitlines():
                     if service.strip() and not service.strip().startswith('*'): subprocess.run(['networksetup', '-setdnsservers', service.strip(), dns_server], capture_output=True, **run_args)
            elif platform.system() == "Linux":
                with open("/etc/resolv.conf", "w") as f: f.write(f"nameserver {dns_server}\n")
            return True
        except: return False

    def revert_system_dns(self):
        run_args = self._get_hidden_subprocess_args()
        try:
            if platform.system() == "Windows":
                 cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Reset-DnsClientServerAddress -Confirm:$false"]
                 subprocess.run(cmd, check=True, capture_output=True, **run_args)
            elif platform.system() == "Darwin":
                result = subprocess.run(['networksetup', '-listallnetworkservices'], check=True, capture_output=True, **run_args)
                for service in result.stdout.splitlines():
                    if service.strip() and not service.strip().startswith('*'): subprocess.run(['networksetup', '-setdnsservers', service.strip(), 'empty'], capture_output=True, **run_args)
            elif platform.system() == "Linux":
                if os.path.exists("/etc/resolv.conf"): os.remove("/etc/resolv.conf")
                # Try to restore symlink if systemd-resolved is used
                if os.path.exists('/run/systemd/resolve/stub-resolv.conf'):
                    os.symlink('/run/systemd/resolve/stub-resolv.conf', '/etc/resolv.conf')
        except: pass

    def cleanup(self):
        self.is_exiting = True
        if self.active_server_info:
            if self.proxy_process:
                self.proxy_process.terminate()
                try:
                    self.proxy_process.wait(timeout=1)
                except: pass
            self.revert_system_dns()

    def start_fetch(self):
        if not self.action_lock.acquire(blocking=False): return
        self.fetch_button.config(state=tk.DISABLED)
        self.bridge_button.config(state=tk.DISABLED)
        
        if not self.server_data:
            self.activate_button.config(state=tk.DISABLED)
            self.tree.delete(*self.tree.get_children())
            
        self.status_var.set("Fetching server and relay lists...")
        threading.Thread(target=self._fetch_and_parse_servers, daemon=True).start()

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
            headers = {'User-Agent': f'{APP_NAME}/1.0'}
            resp_res = requests.get(RESOLVERS_URL, timeout=15, headers=headers); resp_res.raise_for_status()
            self.server_data = self._parse_markdown_list(resp_res.text)
            resp_rel = requests.get(RELAYS_URL, timeout=15, headers=headers); resp_rel.raise_for_status()
            self.relay_data = self._parse_markdown_list(resp_rel.text)
            
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
            
            # --- SAVE CACHE ON SUCCESS ---
            self.save_server_cache()
            
            self.root.after(0, self.on_fetch_complete)
        except Exception as e: 
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
                self.action_lock.release()
            self.root.after(0, lambda: handle_error(str(e)))

    def on_fetch_complete(self):
        self._populate_tree(self.server_data)
        
        self.is_initialized = True
        
        if not self.active_server_info:
            self.check_auto_activation()

        def final_ui_update():
            self.fetch_button.config(state=tk.NORMAL)
            if self.tree.selection(): self.bridge_button.config(state=tk.NORMAL)
            self.action_lock.release()
        self.root.after(0, final_ui_update)
        
    def check_auto_activation(self):
        if not self.preferred_servers: return

        self.tree.selection_set([s['name'] for s in self.server_data if s["name"] in self.preferred_servers])
        servers_to_activate = [s for s in self.server_data if s["name"] in self.preferred_servers]
        
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
            self.activate_button.config(state=tk.NORMAL if (selected_items and os.path.exists(self.proxy_executable)) else tk.DISABLED)
        
        can_bridge = bool(selected_items) and all(next((x for x in self.server_data if x["name"] == name), {}).get('proto_type') == "DNSCrypt" for name in selected_items)
        self.bridge_button.config(state=tk.NORMAL if can_bridge else tk.DISABLED)

        focused_id = self.tree.focus()
        if focused_id:
            s = next((s for s in self.server_data if s["name"] == focused_id), None)
            if s:
                relay_list = self.server_relay_map.get(s["name"], [])
                relay_info = ", ".join(relay_list if isinstance(relay_list, list) else [relay_list]) or "None"
                details = (f"Name: {s['name']}\nProtocol: {s.get('proto_type', 'Unknown')}\nVia Bridge: {relay_info}\n"
                           f"Desc: {s['description']}\nProps: {s['properties']}\n\nSTAMP:\n{s['stamp']}")
                self.details_text.configure(state='normal'); self.details_text.delete(1.0, tk.END)
                self.details_text.insert(tk.END, details); self.details_text.configure(state='disabled')

if __name__ == "__main__":
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
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            else: os.execvp('sudo', ['sudo', sys.executable] + sys.argv)
        except: pass
        sys.exit(0)
    
    app_root = tk.Tk()
    gui = DNSCryptClientGUI(app_root)
    app_root.mainloop()
