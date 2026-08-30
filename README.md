<div align="center">
  <img src="https://github.com/user-attachments/assets/cf5bbdab-b3cf-4a39-955b-ed59efe84505" alt="DNSCrypt Proxy GUI" width="400"/>

  <h1>DNSCrypt Proxy GUI 🛡️</h1>

  <p>A powerful, cross-platform GUI wrapper for the official dnscrypt-proxy.</p>

  [![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)
  [![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgray.svg)](https://github.com/neohiro/dnscrypt-proxy-gui/releases)
  [![Build Status](https://github.com/neohiro/dnscrypt-proxy-gui/actions/workflows/release.yml/badge.svg)](https://github.com/neohiro/dnscrypt-proxy-gui/actions)
  [![License](https://img.shields.io/badge/license-ISC-green.svg)](LICENSE)
</div>

<br />

`dnscrypt-proxy` is a fantastic tool for securing DNS communications, but its power can be daunting for users who prefer a graphical interface. This project provides a user-friendly, cross-platform client that acts as a complete visual controller for the `dnscrypt-proxy` executable.

It allows you to fetch the latest public resolver lists, select one or more servers, and instantly activate them. It handles everything from generating the configuration file to modifying your system's DNS settings and running the proxy in the background.

## ✨ Features

- **Browse & Sort Servers:** Fetches the latest public DNSCrypt resolver list and displays it in an easy-to-sort table.
- **Multi-Server Activation:** Select and activate multiple servers simultaneously for enhanced reliability and speed.
- **Anonymizing Relays:** Apply anonymizing relays to DNSCrypt servers for an extra layer of privacy.
- **Live Status Indicator:** A clear visual indicator shows whether the service is ACTIVE or INACTIVE.
- **Exact DNS Backup & Restore:** Before any change, your current DNS settings are captured and restored verbatim on deactivation or exit. If a crashed session ever left settings behind, the next launch repairs them automatically.
- **System Tray Integration:** Hides the main window to a tray icon, allowing the client to run unobtrusively in the background.
- **Run at Startup:** A simple checkbox lets you configure the client to launch automatically when you log in.
- **Comprehensive Configuration:** A dedicated tab to visually manage the `dnscrypt-proxy.toml` settings.
- **Server Requirements:** Enforce DNSSEC, no-log, and no-filter policies.
- **Network Behavior:** Block IPv6 requests with a single click.
- **Cache Settings:** Fine-tune the cache size and TTL values.
- **Instant Apply:** Configuration changes are applied immediately to the running service with a seamless restart.
- **Session Persistence:** Remembers your last active servers and settings, and can automatically reactivate them on the next launch.
- **Automatic Privilege Elevation:** Intelligently requests administrator/sudo privileges on launch, as they are required for managing network settings.

---

## 🚀 Getting Started

You can either download the pre-compiled standalone executables (Recommended) or run the Python script directly.

### 📥 Option 1: Download Standalone Release (Recommended)

We provide high-quality, pre-built executables for Windows, macOS, and Linux. No Python installation required!

1. Go to the [Releases page](https://github.com/neohiro/dnscrypt-proxy-gui/releases) and download the archive matching your OS and version - e.g. `dnscrypt-proxy-gui-1.2.1-Windows-x64.zip`.
2. Extract it into **its own dedicated folder** (e.g. `C:\Program Files\dnscrypt-proxy-gui\`, `~/Applications/dnscrypt-proxy-gui/`, or `~/dnscrypt-proxy-gui/`). Never extract the contents loose into `Program Files` itself - the folder contains the app plus its runtime libraries.
3. **macOS users:** the app is not codesigned, so on first launch right-click the app and choose **Open** (or allow it in *System Settings → Privacy & Security*). Also grab the official `dnscrypt-proxy` binary from the [DNSCrypt releases page](https://github.com/DNSCrypt/dnscrypt-proxy/releases) and keep it beside the app (or set its path in Configuration → System Paths).
4. **Important:** Download the official `dnscrypt-proxy` executable for your OS from the [DNSCrypt releases page](https://github.com/DNSCrypt/dnscrypt-proxy/releases).
4. Place the `dnscrypt-proxy` executable (e.g., `dnscrypt-proxy.exe` on Windows) **in the same folder** as the GUI executable.
5. Run the GUI executable. (It will automatically request administrator/sudo privileges).

---

### 💻 Option 2: Run from Source

If you prefer to run the Python script directly, follow these steps:

#### 1. Prerequisites
- **Python 3.11+**: Ensure you have Python installed. You can download it from [python.org](https://www.python.org/downloads/).
  - **Debian/Ubuntu**: also install the GUI toolkit with `sudo apt install python3-tk`
  - **Fedora**: `sudo dnf install python3-tkinter`
  - **Arch**: tk is bundled with the `tk` package (`sudo pacman -S tk`)
- **dnscrypt-proxy**: Download the latest version for your OS from the [official DNSCrypt releases page](https://github.com/DNSCrypt/dnscrypt-proxy/releases).
  - On Linux it is usually available from your distro's repositories (`sudo apt install dnscrypt-proxy`) - the GUI will find it at `/usr/bin/dnscrypt-proxy` by default.

#### 2. Get the Code
Clone this repository or download the source code:
```bash
git clone https://github.com/neohiro/dnscrypt-proxy-gui.git
cd dnscrypt-proxy-gui
```

#### 3. Install Dependencies
Create a virtual environment and install the required libraries:
```bash
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt   # requests, pystray, Pillow
```

> The system tray icon needs `pystray` + `Pillow`. Without them the GUI still
> works - closing the window minimises it to your taskbar instead of the tray.

#### 4. Prepare the Directory
Extract the `dnscrypt-proxy` archive you downloaded earlier and place the executable inside the cloned repository. Your directory should look like this:
```text
dnscrypt-proxy-gui/
├── dnscrypt-proxy-gui.PY    # The GUI script
└── dnscrypt-proxy.exe       # The official executable (or `dnscrypt-proxy` on Linux/macOS)
```

#### 5. Run the Script

**Windows:**
```bat
python dnscrypt-proxy-gui.PY
```

**Linux / macOS:**
```bash
python3 dnscrypt-proxy-gui.PY
```

> **Do not run the script through the shell directly** (e.g. `./dnscrypt-proxy-gui.PY`)
> unless you have made it executable first (`chmod +x`). If you see errors like
> `from: not found`, your shell is trying to interpret Python as shell script -
> always launch it via `python3`.

> **Activating servers changes system DNS settings**, which requires elevated
> privileges. On Linux/macOS either start the GUI with `sudo` (using the same
> virtual environment: `sudo .venv/bin/python3 dnscrypt-proxy-gui.PY`) or point
> the Configuration tab's *System Paths* at a proxy/config location your user can write.

---

### System Paths (Linux / macOS)

By default the GUI looks for:

| What | Windows | Linux | macOS |
| --- | --- | --- | --- |
| `dnscrypt-proxy` executable | next to the GUI | `/usr/bin/dnscrypt-proxy` or on `$PATH` | `/usr/local/bin/dnscrypt-proxy` or on `$PATH` |
| Configuration folder | next to the GUI | `/etc/dnscrypt-proxy` | `/usr/local/etc/dnscrypt-proxy` |

Both locations are configurable in the **Configuration → System Paths** section -
set them once and they persist in `settings.json`.

---

## 🛠️ How to Use

1. **Refresh List:** Click **"Refresh Server List"** to fetch the latest resolvers.
2. **Select Servers:** Select one or more servers from the list.
3. **Configure (Optional):** Go to the Configuration tab to adjust settings like DNSSEC, Logging, and IPv6.
4. **Activate:** Click **"Activate Selected Server(s)"**.
5. **Success:** Your DNS traffic is now encrypted! You can close the window to minimize it to the system tray.

> **Note:** When you click Activate, the GUI dynamically generates a `dnscrypt-proxy.toml` file, launches the proxy in the background, and automatically configures your system's network adapter to route DNS queries through `127.0.0.1`. Your previous DNS settings are snapshotted first (`dns_backup.json`) and restored exactly when you deactivate or exit. When you deactivate, it gracefully reverts your settings back to their original state.

> **Troubleshooting:** The app writes a rotating log to `%LOCALAPPDATA%\DNSCryptClientGUI\logs` (Windows), `~/Library/Logs/DNSCryptClientGUI` (macOS) or `~/.cache/dnscryptclientgui/logs` (Linux). Include recent lines when reporting problems.

---

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

Distributed under the ISC License, in parallel with dnscrypt-proxy itself. See [LICENSE](LICENSE) for more information.

## 🙏 Acknowledgments

A huge thank you to the [DNSCrypt team](https://github.com/DNSCrypt) for creating and maintaining the incredible `dnscrypt-proxy` project.

---

<div align="center">
  <a href="http://www.freevisitorcounters.com">Free Counter</a>
  <script type="text/javascript" src="https://www.freevisitorcounters.com/en/home/counter/1631169/t/1"></script>
</div>

<p align="center">
  <a href="https://github.com/sponsors/neohiro"><img src="https://img.shields.io/badge/Sponsor%20on%20GitHub-%E2%9D%A4-EA4AAA?logo=githubsponsors&style=for-the-badge" alt="GitHub Sponsors"></a>&nbsp;&nbsp;
  <a href="https://www.patreon.com/frenzypenguin_media"><img src="https://img.shields.io/badge/Patreon-frenzypenguin__media-F96854?logo=patreon&style=for-the-badge" alt="Support on Patreon"></a>
</p>
