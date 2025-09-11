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

# --- New Imports for Tray Icon and Startup ---
# These libraries are required: pip install pystray Pillow
try:
    from pystray import MenuItem as item, Icon as icon
    from PIL import Image
except ImportError:
    messagebox.showerror("Missing Dependencies",
                         "This application requires 'pystray' and 'Pillow'.\n"
                         "Please install them by running: pip install pystray Pillow")
    sys.exit(1)

# Platform-specific import for startup on Windows
if platform.system() == "Windows":
    import winreg

# --- Constants ---
APP_NAME = "DNSCryptClientGUI"
RESOLVERS_URL = "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md"
CONFIG_FILE = "dnscrypt-proxy.toml"
SETTINGS_FILE = "settings.json" # File to store persistent settings

def is_admin():
    """Check for administrator privileges."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

class DNSCryptClientGUI:
    """
    A GUI application to browse, select, and activate DNSCrypt servers.
    This tool controls the official dnscrypt-proxy executable to route system DNS traffic.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("DNSCrypt Client & Controller")
        self.root.geometry("1000x800")
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
        # Style for the new config tab
        self.style.configure("Config.TFrame", padding=15)


        self.server_data = []
        self.active_server_info = []
        self.proxy_process = None
        self.last_sort_col = None
        self.last_sort_rev = False
        
        # --- State Management for UI Stability ---
        self.action_lock = threading.Lock() # Prevents concurrent activate/deactivate/fetch operations
        self.tray_icon = None # The active icon object
        self.tray_thread = None # The thread running the icon
        self.tray_lock = threading.Lock()

        # --- Variables for Configuration Tab ---
        self.block_ipv6_var = tk.BooleanVar()
        self.require_dnssec_var = tk.BooleanVar()
        self.require_nolog_var = tk.BooleanVar()
        self.require_nofilter_var = tk.BooleanVar()
        self.cache_size_var = tk.StringVar()
        self.cache_neg_ttl_var = tk.StringVar()
        self.cache_min_ttl_var = tk.StringVar()

        self.settings = self.load_settings() # Load persistent settings on start
        
        # Apply loaded settings to variables
        self.block_ipv6_var.set(self.settings.get("block_ipv6", False))
        self.require_dnssec_var.set(self.settings.get("require_dnssec", False))
        self.require_nolog_var.set(self.settings.get("require_nolog", False))
        self.require_nofilter_var.set(self.settings.get("require_nofilter", False))
        self.cache_size_var.set(self.settings.get("cache_size", "512"))
        self.cache_neg_ttl_var.set(self.settings.get("cache_neg_ttl", "60"))
        self.cache_min_ttl_var.set(self.settings.get("cache_min_ttl", "60"))

        atexit.register(self.cleanup)
        
        self.setup_widgets()
        self.setup_tray_and_close_protocol()
        
        self.check_proxy_executable()
        self.check_startup_status()
        self.start_fetch()

    def check_proxy_executable(self):
        """Checks if the dnscrypt-proxy executable is present."""
        self.proxy_executable = "dnscrypt-proxy"
        if platform.system() == "Windows":
            self.proxy_executable += ".exe"
            
        if not os.path.exists(self.proxy_executable):
            messagebox.showwarning("Executable Not Found",
                                   f"'{self.proxy_executable}' not found in the same directory.\n\n"
                                   "Please download it from the official DNSCrypt GitHub page and place it here. "
                                   "Activation will be disabled.")
            self.activate_button.config(state=tk.DISABLED)

    def setup_widgets(self):
        """Creates and arranges all the GUI widgets."""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Activation Frame (stays on top) ---
        activation_frame = ttk.Frame(main_frame, padding=5, relief=tk.RIDGE)
        activation_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.status_indicator = ttk.Label(activation_frame, text="STATUS: INACTIVE", style="Inactive.TLabel")
        self.status_indicator.pack(side=tk.LEFT, padx=10)
        
        self.active_server_label = ttk.Label(activation_frame, text="No server active.")
        self.active_server_label.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=10)
        
        self.startup_var = tk.BooleanVar()
        startup_check = ttk.Checkbutton(activation_frame, text="Run at system startup", variable=self.startup_var, command=self.toggle_startup)
        startup_check.pack(side=tk.LEFT, padx=10)

        self.activate_button = ttk.Button(activation_frame, text="Activate Selected Server(s)", command=self.toggle_activation, state=tk.DISABLED)
        self.activate_button.pack(side=tk.RIGHT, padx=10, pady=5)

        # --- Tabbed Interface ---
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)

        # --- Servers Tab ---
        servers_tab = ttk.Frame(notebook, padding=10)
        notebook.add(servers_tab, text="Servers")
        
        top_frame = ttk.Frame(servers_tab)
        top_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(top_frame, text="Available Public Servers", style="Header.TLabel").pack(side=tk.LEFT)
        self.fetch_button = ttk.Button(top_frame, text="Refresh Server List", command=self.start_fetch)
        self.fetch_button.pack(side=tk.RIGHT)

        tree_frame = ttk.Frame(servers_tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        columns = ("name", "no-log", "dnssec", "no-filter")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="extended")
        
        self.tree.heading("name", text="Server Name", command=lambda: self.sort_by_column("name"))
        self.tree.column("name", width=200, stretch=tk.YES)
        self.tree.heading("no-log", text="No Logs", command=lambda: self.sort_by_column("no-log"))
        self.tree.column("no-log", width=80, anchor=tk.CENTER)
        self.tree.heading("dnssec", text="DNSSEC", command=lambda: self.sort_by_column("dnssec"))
        self.tree.column("dnssec", width=80, anchor=tk.CENTER)
        self.tree.heading("no-filter", text="No Filter", command=lambda: self.sort_by_column("no-filter"))
        self.tree.column("no-filter", width=80, anchor=tk.CENTER)

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

        # --- Configuration Tab ---
        config_tab = ttk.Frame(notebook, style="Config.TFrame")
        notebook.add(config_tab, text="Configuration")
        self._create_config_tab(config_tab)
        
        # --- Status Bar (stays on bottom) ---
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, style="Status.TLabel", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var.set("Ready.")

    def _create_config_tab(self, parent):
        """Creates the widgets for the configuration tab."""
        # Requirements Frame
        req_frame = ttk.LabelFrame(parent, text="Server Requirements", padding=10)
        req_frame.pack(fill=tk.X, pady=5, padx=5)
        
        ttk.Checkbutton(req_frame, text="Require servers to support DNSSEC", variable=self.require_dnssec_var, command=self.update_config_and_restart_proxy).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(req_frame, text="Require servers to be non-logging", variable=self.require_nolog_var, command=self.update_config_and_restart_proxy).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(req_frame, text="Require servers to be non-filtering", variable=self.require_nofilter_var, command=self.update_config_and_restart_proxy).pack(anchor=tk.W, pady=2)

        # Network Frame
        net_frame = ttk.LabelFrame(parent, text="Network Behavior", padding=10)
        net_frame.pack(fill=tk.X, pady=5, padx=5)
        ttk.Checkbutton(net_frame, text="Block IPv6 DNS requests", variable=self.block_ipv6_var, command=self.update_config_and_restart_proxy).pack(anchor=tk.W, pady=2)

        # Cache Frame
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
    
    # --- Settings Persistence ---
    def save_settings(self):
        """Saves current settings to a JSON file."""
        settings_to_save = {
            "was_active": bool(self.active_server_info),
            "last_active_servers": [s['name'] for s in self.active_server_info],
            "block_ipv6": self.block_ipv6_var.get(),
            "require_dnssec": self.require_dnssec_var.get(),
            "require_nolog": self.require_nolog_var.get(),
            "require_nofilter": self.require_nofilter_var.get(),
            "cache_size": self.cache_size_var.get(),
            "cache_neg_ttl": self.cache_neg_ttl_var.get(),
            "cache_min_ttl": self.cache_min_ttl_var.get()
        }
        try:
            with open(SETTINGS_FILE, 'w') as f:
                json.dump(settings_to_save, f, indent=4)
        except Exception as e:
            print(f"Error saving settings: {e}")

    def load_settings(self):
        """Loads settings from a JSON file."""
        try:
            with open(SETTINGS_FILE, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                "was_active": False, "last_active_servers": [],
                "block_ipv6": False, "require_dnssec": False, "require_nolog": False,
                "require_nofilter": False, "cache_size": "512", "cache_neg_ttl": "60",
                "cache_min_ttl": "60"
            }

    # --- Tray Icon and Window Management (Bug Fix Applied) ---
    def setup_tray_and_close_protocol(self):
        """Sets up the window close protocol to hide to tray."""
        self.root.protocol('WM_DELETE_WINDOW', self.hide_window)

    def hide_window(self):
        """Hides the main window and runs the tray icon in a separate thread."""
        self.root.withdraw()
        
        def start_icon_thread():
            # Create a new icon object each time to avoid reusing an invalid handle
            image = Image.new('RGB', (64, 64), 'green')
            menu = (item('Show', self.show_window, default=True), item('Exit', self.quit_app))
            
            # The icon object must be stored on self to be accessible by show_window/quit_app
            with self.tray_lock:
                self.tray_icon = icon(APP_NAME, image, "DNSCrypt Client", menu)
            
            self.tray_icon.run() # This is a blocking call
            
            # Once run() returns (after stop()), clear the object reference
            with self.tray_lock:
                self.tray_icon = None

        with self.tray_lock:
            # Only start a new thread if one isn't already alive
            if not (self.tray_thread and self.tray_thread.is_alive()):
                self.tray_thread = threading.Thread(target=start_icon_thread, daemon=True)
                self.tray_thread.start()

    def show_window(self):
        """Stops the tray icon thread and shows the main window."""
        with self.tray_lock:
            if self.tray_icon:
                self.tray_icon.stop()
        
        self.root.deiconify()
        self.root.lift()
        self.root.attributes('-topmost', 1)
        self.root.attributes('-topmost', 0)

    def quit_app(self):
        """Stops the tray icon thread and closes the application."""
        with self.tray_lock:
            if self.tray_icon:
                self.tray_icon.stop()
        self.root.destroy()

    # --- Run at Startup Logic ---
    def get_startup_path_and_command(self):
        script_path = os.path.abspath(sys.argv[0])
        command = f'"{sys.executable}" "{script_path}"'
        return script_path, command

    def toggle_startup(self):
        if self.startup_var.get():
            self.add_to_startup()
        else:
            self.remove_from_startup()

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
                    f.write(f"[Desktop Entry]\nType=Application\nExec={command}\n"
                            f"X-GNOME-Autostart-enabled=true\nName={APP_NAME}\n")
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
                    winreg.QueryValueEx(key, APP_NAME)
                    is_startup = True
            elif system == "Linux":
                is_startup = os.path.exists(os.path.expanduser(f"~/.config/autostart/{APP_NAME}.desktop"))
            elif system == "Darwin":
                is_startup = os.path.exists(os.path.expanduser(f"~/Library/LaunchAgents/com.{APP_NAME}.plist"))
        except FileNotFoundError: is_startup = False
        except Exception: is_startup = False
        self.startup_var.set(is_startup)
    
    # --- Core Application Logic ---
    def sort_by_column(self, col):
        reverse = col == self.last_sort_col and not self.last_sort_rev
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        l.sort(key=lambda t: str(t[0]), reverse=reverse)
        for index, (val, k) in enumerate(l): self.tree.move(k, '', index)
        self.last_sort_col = col; self.last_sort_rev = reverse

    def _populate_tree(self, server_list):
        self.tree.delete(*self.tree.get_children())
        for server in server_list:
            values = (server["name"], server["no-log"], server["dnssec"], server["no-filter"])
            self.tree.insert("", tk.END, values=values, iid=server["name"])
        self.status_var.set(f"Fetched {len(self.server_data)} DNSCrypt servers.")

    def toggle_activation(self):
        # Prevent starting a new action if one is already running
        if not self.action_lock.acquire(blocking=False):
            return

        def task():
            try:
                if self.active_server_info:
                    self.deactivate_dns()
                else:
                    # Reading from the UI should be done via the main thread
                    selected_items = self.tree.selection()
                    if not selected_items:
                        self.root.after(0, lambda: messagebox.showerror("Error", "Please select one or more servers from the list to activate."))
                        return
                    server_list = [s for s in self.server_data if s["name"] in selected_items]
                    if server_list:
                        self.activate_dns(server_list)
            finally:
                # Always release the lock when the operation is complete
                self.action_lock.release()

        # Run the activation/deactivation logic in a separate thread to keep the UI responsive
        threading.Thread(target=task, daemon=True).start()

    def update_config_and_restart_proxy(self, event=None):
        """Saves settings and restarts the proxy if it's active."""
        self.save_settings()
        if self.active_server_info:
            if not self.action_lock.acquire(blocking=False):
                return
            
            def task():
                try:
                    self.root.after(0, lambda: self.status_var.set("Configuration changed. Restarting proxy..."))
                    current_servers = self.active_server_info
                    self.deactivate_dns()
                    # Only reactivate if deactivation was successful
                    if not self.active_server_info:
                        self.activate_dns(current_servers)
                finally:
                    self.action_lock.release()
            
            threading.Thread(target=task, daemon=True).start()

    def _generate_config_content(self, server_list):
        """Generates the content for the dnscrypt-proxy.toml file."""
        server_names_list = [s['name'] for s in server_list]
        try: cache_size = int(self.cache_size_var.get())
        except (ValueError, TypeError): cache_size = 512
        try: cache_min_ttl = int(self.cache_min_ttl_var.get())
        except (ValueError, TypeError): cache_min_ttl = 60
        try: cache_neg_ttl = int(self.cache_neg_ttl_var.get())
        except (ValueError, TypeError): cache_neg_ttl = 60

        config_lines = [
            '# This file is auto-generated by the DNSCrypt Client GUI',
            "listen_addresses = ['127.0.0.1:53']",
            f"server_names = {repr(server_names_list)}", '',
            '# --- Global Settings ---',
            f'block_ipv6 = {str(self.block_ipv6_var.get()).lower()}',
            f'require_dnssec = {str(self.require_dnssec_var.get()).lower()}',
            f'require_nolog = {str(self.require_nolog_var.get()).lower()}',
            f'require_nofilter = {str(self.require_nofilter_var.get()).lower()}', '',
            '# --- Cache Settings ---',
            'cache = true',
            f'cache_size = {cache_size}',
            f'cache_min_ttl = {cache_min_ttl}',
            f'cache_neg_ttl = {cache_neg_ttl}', '',
            '# --- Static Server Definitions ---'
        ]
        for server_info in server_list:
            config_lines.extend([f"\n[static.'{server_info['name']}']", f"stamp = '{server_info['stamp']}'"])
        return "\n".join(config_lines)

    def activate_dns(self, server_list):
        # UI updates must be scheduled to run on the main thread
        def update_ui(key, value):
            self.root.after(0, lambda: self.status_var.set(value) if key == 'status' else None)
            if key == 'disable_button': self.root.after(0, lambda: self.activate_button.config(state=tk.DISABLED))

        update_ui('status', f"Activating {len(server_list)} servers...")
        update_ui('disable_button', True)

        config_content = self._generate_config_content(server_list)
        with open(CONFIG_FILE, "w", encoding='utf-8') as f: f.write(config_content)
        
        try:
            creation_flags = 0
            if platform.system() == "Windows": creation_flags = subprocess.CREATE_NO_WINDOW
            self.proxy_process = subprocess.Popen(
                [f"./{self.proxy_executable}", "-config", CONFIG_FILE],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=creation_flags
            )
            time.sleep(2) 
            if self.proxy_process.poll() is not None:
                stdout, stderr = self.proxy_process.communicate()
                error_message = f"dnscrypt-proxy failed to start (exit code: {self.proxy_process.returncode}).\n\n"
                error_message += f"Error Details:\n{stderr.strip()}" if stderr else (f"Details:\n{stdout.strip()}" if stdout else "No specific error message.")
                raise Exception(error_message)
        except Exception as e:
            update_ui('status', "Error starting proxy.")
            self.root.after(0, lambda: messagebox.showerror("Proxy Startup Error", str(e)))
            self.cleanup(); return

        if not self.set_system_dns("127.0.0.1"):
             update_ui('status', "Failed to set system DNS. Reverting...")
             self.root.after(0, lambda: messagebox.showerror("DNS Error", "Could not set system DNS. You may need to do it manually."))
             self.cleanup(); return
        
        def final_success_ui():
            self.active_server_info = server_list
            self.activate_button.config(text="Deactivate", state=tk.NORMAL)
            self.status_indicator.config(text="STATUS: ACTIVE", style="Active.TLabel")
            server_names_list = [s['name'] for s in server_list]
            active_names = ", ".join(server_names_list)
            if len(active_names) > 80: active_names = f"{len(server_list)} servers active"
            self.active_server_label.config(text=f"Active: {active_names}")
            self.status_var.set(f"Successfully activated {len(server_list)} servers.")
        
        self.root.after(0, final_success_ui)
        self.save_settings()

    def deactivate_dns(self):
        def update_ui_state():
            self.status_var.set("Deactivating...")
            self.activate_button.config(state=tk.DISABLED)

        self.root.after(0, update_ui_state)

        if self.proxy_process:
            self.proxy_process.terminate(); self.proxy_process.wait(); self.proxy_process = None
        self.revert_system_dns()
        
        def final_ui_reset():
            self.active_server_info = []
            self.activate_button.config(text="Activate Selected Server(s)", state=tk.NORMAL if self.tree.selection() else tk.DISABLED)
            self.status_indicator.config(text="STATUS: INACTIVE", style="Inactive.TLabel")
            self.active_server_label.config(text="No server active.")
            self.status_var.set("Deactivated. System DNS restored.")
        
        self.root.after(0, final_ui_reset)

        if os.path.exists(CONFIG_FILE): os.remove(CONFIG_FILE)
        self.save_settings()

    def set_system_dns(self, dns_server):
        system = platform.system()
        creation_flags = subprocess.CREATE_NO_WINDOW if system == "Windows" else 0
        try:
            if system == "Windows":
                for interface in ["Wi-Fi", "Ethernet"]:
                    subprocess.run(f'netsh interface ipv4 set dns name="{interface}" static {dns_server}', check=True, capture_output=True, text=True, creationflags=creation_flags)
            elif system == "Darwin":
                subprocess.run(['networksetup', '-setdnsservers', 'Wi-Fi', dns_server], check=True)
            elif system == "Linux":
                with open("/etc/resolv.conf", "w") as f: f.write(f"nameserver {dns_server}\n")
            return True
        except (subprocess.CalledProcessError, PermissionError, FileNotFoundError) as e:
            print(f"Failed to set DNS for an interface: {e}")
        return True

    def revert_system_dns(self):
        system = platform.system()
        creation_flags = subprocess.CREATE_NO_WINDOW if system == "Windows" else 0
        try:
            if system == "Windows":
                 for interface in ["Wi-Fi", "Ethernet"]:
                    subprocess.run(f'netsh interface ipv4 set dns name="{interface}" dhcp', check=True, capture_output=True, text=True, creationflags=creation_flags)
            elif system == "Darwin":
                subprocess.run(['networksetup', '-setdnsservers', 'Wi-Fi', 'empty'], check=True)
            elif system == "Linux":
                if os.path.exists("/etc/resolv.conf"): os.remove("/etc/resolv.conf")
                os.symlink('/run/systemd/resolve/stub-resolv.conf', '/etc/resolv.conf')
        except Exception as e:
            self.root.after(0, lambda: messagebox.showwarning("DNS Revert Failed", f"Could not automatically revert DNS settings: {e}\n\nPlease set your network adapter to obtain DNS automatically."))

    def cleanup(self):
        if self.active_server_info:
            print("Performing cleanup...")
            self.deactivate_dns()

    def start_fetch(self):
        if not self.action_lock.acquire(blocking=False):
            return

        self.fetch_button.config(state=tk.DISABLED)
        self.activate_button.config(state=tk.DISABLED)
        self.status_var.set("Fetching server list...")
        self.tree.delete(*self.tree.get_children())
        threading.Thread(target=self._fetch_and_parse_servers, daemon=True).start()

    def _fetch_and_parse_servers(self):
        try:
            headers = {'User-Agent': f'{APP_NAME}/1.0'}
            response = requests.get(RESOLVERS_URL, timeout=15, headers=headers)
            response.raise_for_status(); response.encoding = 'utf-8'
            self.server_data.clear()
            lines, current_server = response.text.splitlines(), None
            for line in lines:
                line = line.strip()
                if line.startswith('## '):
                    if current_server and 'stamp' in current_server: self.server_data.append(current_server)
                    current_server = {'name': line[3:].strip(), 'description': '', 'protocols': 'dnscrypt'}
                elif current_server:
                    if line.startswith('sdns://'):
                        if 'stamp' not in current_server: current_server['stamp'] = line
                    elif line and 'stamp' not in current_server: current_server['description'] += line + '\n'
            if current_server and 'stamp' in current_server: self.server_data.append(current_server)
            
            for server in self.server_data:
                desc_lower = server['description'].lower(); props = []
                for prop in ['no-log', 'dnssec', 'no-filter']:
                    keywords = [prop, prop.replace('-', ' ')]; 
                    if prop == 'no-log': keywords.append('no-logging')
                    if prop == 'no-filter': keywords.append('non-filtering')
                    if any(k in desc_lower for k in keywords):
                        server[prop] = '✓'; props.append(prop)
                    else: server[prop] = '✗'
                server['properties'] = ', '.join(props)
                server['description'] = server['description'].replace('\n', ' ').strip()
            self.root.after(0, self.on_fetch_complete)
        except requests.RequestException as e: self.root.after(0, lambda: self.status_var.set(f"Network error: {e}"))
        except Exception as e: self.root.after(0, lambda: self.status_var.set(f"Parse error: {e}"))
        finally:
            def final_ui_update():
                self.fetch_button.config(state=tk.NORMAL)
                # Re-enable activate button only if not active and something is selected
                if not self.active_server_info and self.tree.selection():
                    self.activate_button.config(state=tk.NORMAL)
                self.action_lock.release()
            self.root.after(0, final_ui_update)

    def on_fetch_complete(self):
        self._populate_tree(self.server_data)
        if self.settings.get("was_active"):
            server_names_to_activate = self.settings.get("last_active_servers", [])
            if server_names_to_activate:
                servers_to_activate = [s for s in self.server_data if s["name"] in server_names_to_activate]
                if len(servers_to_activate) == len(server_names_to_activate):
                    self.tree.selection_set([s['name'] for s in servers_to_activate])
                    self.toggle_activation() # Will use the new selection
                else:
                    self.status_var.set("Could not find all previously active servers. Deactivating.")
                    if self.active_server_info: self.toggle_activation()

    def on_server_select(self, event):
        selected_items = self.tree.selection()
        if not self.active_server_info:
            if selected_items and os.path.exists(self.proxy_executable):
                self.activate_button.config(state=tk.NORMAL)
            else:
                self.activate_button.config(state=tk.DISABLED)

        focused_id = self.tree.focus()
        if not focused_id: return
        selected_server = next((s for s in self.server_data if s["name"] == focused_id), None)
        if selected_server:
            details = (f"Name:        {selected_server['name']}\n"
                       f"Description: {selected_server['description']}\n"
                       f"Properties:  {selected_server['properties']}\n\n"
                       f"DNSCRYPT STAMP (sdns://):\n{selected_server['stamp']}")
            self.details_text.configure(state='normal'); self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, details); self.details_text.configure(state='disabled')

if __name__ == "__main__":
    # Set the current working directory to the script's directory. This is crucial
    # for locating the dnscrypt-proxy executable and config files.
    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))
    os.chdir(application_path)
    
    if not is_admin():
        try:
            if platform.system() == "Windows":
                import ctypes
                # The parameters for the new process must include the script's own path.
                # We also robustly quote each argument to handle paths with spaces.
                params = " ".join([f'"{arg}"' for arg in sys.argv])
                
                # Attempt to re-launch with admin privileges.
                hinstance = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
                
                # If the re-launch fails (e.g., user clicks "No" on UAC), show an error.
                if hinstance <= 32:
                    error_message = (
                        f"This application requires administrator privileges to run.\n\n"
                        f"The attempt to automatically elevate failed with error code: {hinstance}\n\n"
                        f"Please right-click the application and select 'Run as administrator'."
                    )
                    # Use the native Windows MessageBoxW for the error dialog, as Tkinter isn't initialized.
                    # 0x10 is MB_ICONERROR, 0x0 is MB_OK.
                    ctypes.windll.user32.MessageBoxW(None, error_message, "Administrator Privileges Required", 0x10 | 0x0)
            else:
                # Non-Windows elevation logic remains the same.
                os.execvp('sudo', ['sudo', sys.executable] + sys.argv)
        except Exception as e:
            # Catch any other unexpected exceptions during elevation.
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, f"An unexpected error occurred while trying to elevate privileges:\n\n{e}", "Startup Error", 0x10 | 0x0)
        finally:
            # The original non-admin instance must always exit.
            sys.exit(0)
    
    # If we've reached this point, we are running with admin privileges.
    app_root = tk.Tk()
    gui = DNSCryptClientGUI(app_root)
    app_root.mainloop()