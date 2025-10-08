# dnscrypt-proxy-gui
A simple GUI to set up [dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy)

## DNSCrypt Client GUI 🛡️
A powerful and cross-platform GUI wrapper for the official dnscrypt-proxy, allowing you to easily browse, configure, and secure your system's DNS traffic.

### About The Project
dnscrypt-proxy is a fantastic command-line tool for securing DNS communications, but its power can be daunting for users who prefer a graphical interface. This project provides a user-friendly Python and Tkinter-based client that acts as a complete controller for the dnscrypt-proxy executable.

It allows you to fetch the latest public resolver lists, select one or more servers, and instantly activate them. It handles everything from generating the configuration file to modifying your system's DNS settings and running the proxy in the background. You can also use this GUI to set up the .TOML file and use dnscrypt-proxy without after that.

### Features ✨
- Browse & Sort Servers: Fetches the latest public DNSCrypt resolver list and displays it in an easy-to-sort table.

- Multi-Server Activation: Select and activate multiple servers simultaneously for enhanced reliability and speed.

- Live Status Indicator: A clear visual indicator shows whether the service is ACTIVE or INACTIVE.

- System Tray Integration: Hides the main window to a tray icon, allowing the client to run unobtrusively in the background.

- Run at Startup: A simple checkbox lets you configure the client to launch automatically when you log in.

- Comprehensive Configuration: A dedicated tab to visually manage the dnscrypt-proxy.toml settings.

- Server Requirements: Enforce DNSSEC, no-log, and no-filter policies.

- Network Behavior: Block IPv6 requests with a single click.

- Cache Settings: Fine-tune the cache size and TTL values.

- Instant Apply: Configuration changes are applied immediately to the running service with a seamless restart.

- Session Persistence: Remembers your last active servers and settings, and can automatically reactivate them on the next launch.

- Cross-Platform: Works on Windows, macOS, and Linux with platform-specific logic for DNS management and startup tasks.

- Automatic Privilege Elevation: Intelligently requests administrator/sudo privileges on launch, as they are required for managing network settings.

## How It Works ⚙️
This application is a Python wrapper that automates the entire process of using dnscrypt-proxy:

- Fetches: It downloads the official list of public DNSCrypt resolvers.

- Configures: When you select servers and click "Activate," it dynamically generates a dnscrypt-proxy.toml configuration file with your chosen servers and settings from the Configuration tab.

- Executes: It launches the dnscrypt-proxy.exe (or equivalent) process in the background, pointing it to the newly generated configuration file.

- Redirects: It automatically changes your system's network adapter settings to use 127.0.0.1 as the DNS server, routing all DNS queries through the local proxy.

- Restores: When you deactivate the service, it terminates the proxy process and gracefully reverts your system's DNS settings back to their original state (DHCP/Automatic).

## Getting Started 🚀
Follow these steps to get the client up and running on your system.

### Prerequisites
>> You can use the .exe file on Windows directly. For Linux:

Python 3.x: Ensure you have Python installed. You can download it from python.org.

dnscrypt-proxy Executable: This client controls the official proxy; it does not include it.

Download the latest version for your OS from the official DNSCrypt releases page.

Unzip the archive and place the dnscrypt-proxy executable file in the same directory as the Python script.

Python Libraries: Install the required packages using pip.



pip install requests pystray Pillow
Installation & Usage
Get the Code: Clone this repository or download the DNSCRYPTCLIENT.py script.

Shell

git clone https://github.com/neohiro/dnscrypt-proxy-gui.git

cd dnscrypt-proxy-gui

Place the Executable: Make sure your directory looks like this:

├── DNSCRYPTCLIENT.py       # The script you downloaded

└── dnscrypt-proxy.exe      # The official executable (or `dnscrypt-proxy` on Linux/macOS)

Run the Script: Execute the script from your terminal. It will request administrator privileges.

Shell

python DNSCRYPTCLIENT.py
Activate a Server:

Click "Refresh Server List" to fetch the latest resolvers.

Select one or more servers from the list.

(Optional) Go to the Configuration tab to adjust settings.

Click "Activate Selected Server(s)".

Your DNS traffic is now encrypted! You can close the window to minimize it to the system tray.

## Contributing 🤝
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".

- Fork the Project

- Create your Feature Branch (git checkout -b feature/AmazingFeature)

- Commit your Changes (git commit -m 'Add some AmazingFeature')

- Push to the Branch (git push origin feature/AmazingFeature)

- Open a Pull Request

## License
Distributed under the ICS License, in parallel with dnscrypt-proxy itself. See LICENSE for more information.

## Acknowledgments
A huge thank you to the DNSCrypt team for creating and maintaining the incredible dnscrypt-proxy project.
