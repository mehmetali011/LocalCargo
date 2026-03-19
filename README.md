# LocalCargo

**Secure, cross-platform, and blazing-fast local network folder synchronization.**

LocalCargo allows you to seamlessly sync directories between Windows, macOS, and Linux devices over your local network. It runs quietly in the background as a system daemon and uses AES-256 end-to-end encryption to keep your files safe.

## Features

- **Cross-Platform:** Works natively on Windows, macOS, and Linux.
- **Background Daemon:** Starts automatically on boot and runs silently in the background.
- **End-to-End Encryption:** All file transfers are secured with AES-256-CTR encryption.
- **Zero Configuration Hell:** An easy-to-use CLI wizard sets up everything for you.
- **Self-Destruct Protocol:** A clean `remove` command that wipes all traces and zombie processes from your system.

---
## Quick Start (For Users)

You don't need Python or any dependencies to run LocalCargo. 

### Package Managers (Coming Soon)
Once the project is published to official package repositories, you will be able to install it globally with a single command:

```bash
# Windows (Winget) - Work in progress
# winget install localcargo

# macOS / Linux (Homebrew) - Work in progress
# brew install localcargo
```

### Manual Installation
1. Go to the [Releases](../../releases/latest) page and download the `.zip` file for your operating system.
2. Extract the archive.
3. Open your terminal in the extracted folder and run:
   
   ```bash
   # Windows
   .\LocalCargo.exe setup
   
   # macOS / Linux
   ./LocalCargo setup
   ```
4. Follow the interactive wizard to pair your devices. That's it!

> **Note on "Untrusted Publisher" Warnings:**
> Because these executables are open-source and not signed with a paid developer certificate, your operating system's security features might flag them upon first run.

---

## Commands

Once installed and added to your system PATH, you can manage the LocalCargo daemon from anywhere using these CLI commands:

| Command | Description |
| :--- | :--- |
| `localcargo start` | Starts the background sync daemon. |
| `localcargo stop` | Suspends the background daemon safely. |
| `localcargo status` | Checks if the daemon is currently running (shows PID). |
| `localcargo remove` | Stops the service, removes autostart entries, and deletes the app. |
| `localcargo setup` | Re-runs the initial pairing and configuration wizard. |
| `localcargo menu` | Opens the interactive control panel. |

---

## For Developers (Build from Source)

If you want to contribute, test the source code, or build the executables yourself:

**1. Clone the repository**
```bash
git clone [https://github.com/mehmetali011/LocalCargo.git](https://github.com/mehmetali011/LocalCargo.git)
cd LocalCargo
```

## License
This project is licensed under the MIT License.