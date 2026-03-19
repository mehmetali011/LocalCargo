import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

import receiver
import sender
import setup as setup_wizard

APP_NAME = "LocalCargo"
MAC_LABEL = "com.localcargo.daemon"
LINUX_SERVICE = "localcargo.service"


def _app_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


APP_DIR = _app_dir()
SETTINGS_PATH = APP_DIR / "settings.json"
PID_PATH = APP_DIR / ".localcargo.pid"

# Keep runtime consistent even when started by OS autostart.
os.chdir(APP_DIR)


def _daemon_command():
    if getattr(sys, "frozen", False):
        return [str(Path(sys.executable).resolve()), "daemon"]
    return [sys.executable, str(Path(__file__).resolve()), "daemon"]


def _pid_exists(pid):
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _read_pid():
    try:
        return int(PID_PATH.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _write_pid(pid):
    PID_PATH.write_text(str(pid), encoding="utf-8")


def _remove_pid():
    try:
        PID_PATH.unlink()
    except OSError:
        pass


def is_running():
    pid = _read_pid()
    if _pid_exists(pid):
        return True, pid
    if pid is not None:
        _remove_pid()
    return False, None


def _stop_process_by_pid(pid):
    system = platform.system()
    if system == "Windows":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return

    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return

    deadline = time.time() + 5
    while time.time() < deadline:
        if not _pid_exists(pid):
            return
        time.sleep(0.2)

    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _windows_startup_file():
    startup_dir = (
        Path(os.environ.get("APPDATA", ""))
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup"
    )
    return startup_dir / f"{APP_NAME}.cmd"


def _mac_plist_path():
    return Path.home() / "Library" / "LaunchAgents" / f"{MAC_LABEL}.plist"


def _linux_service_path():
    return Path.home() / ".config" / "systemd" / "user" / LINUX_SERVICE


def is_autostart_installed():
    system = platform.system()
    if system == "Windows":
        return _windows_startup_file().exists()
    if system == "Darwin":
        return _mac_plist_path().exists()
    if system == "Linux":
        return _linux_service_path().exists()
    return False


def install_autostart():
    system = platform.system()
    cmd = _daemon_command()

    if system == "Windows":
        startup_file = _windows_startup_file()
        startup_file.parent.mkdir(parents=True, exist_ok=True)
        command_str = subprocess.list2cmdline(cmd)
        startup_file.write_text(
            "@echo off\n"
            f'cd /d "{APP_DIR}"\n'
            f"start \"\" {command_str}\n",
            encoding="utf-8",
        )
        print("[+] Windows Startup entry created.")
        return

    if system == "Darwin":
        plist_path = _mac_plist_path()
        plist_path.parent.mkdir(parents=True, exist_ok=True)
        args_xml = "\n".join(
            f"        <string>{xml_escape(str(arg))}</string>" for arg in cmd
        )
        plist_content = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0">\n'
            "<dict>\n"
            "    <key>Label</key>\n"
            f"    <string>{MAC_LABEL}</string>\n"
            "    <key>ProgramArguments</key>\n"
            "    <array>\n"
            f"{args_xml}\n"
            "    </array>\n"
            "    <key>RunAtLoad</key>\n"
            "    <true/>\n"
            "    <key>KeepAlive</key>\n"
            "    <true/>\n"
            "    <key>WorkingDirectory</key>\n"
            f"    <string>{xml_escape(str(APP_DIR))}</string>\n"
            "</dict>\n"
            "</plist>\n"
        )
        plist_path.write_text(plist_content, encoding="utf-8")
        subprocess.run(
            ["launchctl", "unload", str(plist_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        subprocess.run(
            ["launchctl", "load", str(plist_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        print("[+] macOS LaunchAgent created.")
        return

    if system == "Linux":
        service_path = _linux_service_path()
        service_path.parent.mkdir(parents=True, exist_ok=True)
        exec_start = " ".join(f'"{str(part)}"' for part in cmd)
        service_content = (
            "[Unit]\n"
            "Description=LocalCargo Sync Daemon\n\n"
            "[Service]\n"
            f"WorkingDirectory={APP_DIR}\n"
            f"ExecStart={exec_start}\n"
            "Restart=always\n"
            "RestartSec=2\n\n"
            "[Install]\n"
            "WantedBy=default.target\n"
        )
        service_path.write_text(service_content, encoding="utf-8")
        subprocess.run(
            ["systemctl", "--user", "daemon-reload"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        subprocess.run(
            ["systemctl", "--user", "enable", "--now", LINUX_SERVICE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        print("[+] Linux user service created.")
        return

    print("[!] Autostart is not supported on this operating system.")


def remove_autostart():
    system = platform.system()
    try:
        if system == "Windows":
            startup_file = _windows_startup_file()
            if startup_file.exists():
                startup_file.unlink()
        elif system == "Darwin":
            plist_path = _mac_plist_path()
            subprocess.run(
                ["launchctl", "unload", str(plist_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if plist_path.exists():
                plist_path.unlink()
        elif system == "Linux":
            service_path = _linux_service_path()
            subprocess.run(
                ["systemctl", "--user", "disable", "--now", LINUX_SERVICE],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if service_path.exists():
                service_path.unlink()
            subprocess.run(
                ["systemctl", "--user", "daemon-reload"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        print("[OK] Autostart entries removed.")
    except Exception as e:
        print(f"[!] Failed to remove autostart entries: {e}")


def _run_receiver():
    try:
        receiver.start_receiver()
    except Exception as e:
        print(f"[!] Receiver stopped unexpectedly: {e}")


def _run_sender():
    try:
        sender.start_sender()
    except Exception as e:
        print(f"[!] Sender stopped unexpectedly: {e}")


def run_daemon():
    if not SETTINGS_PATH.exists():
        return 1

    _write_pid(os.getpid())
    try:
        receiver_thread = threading.Thread(target=_run_receiver, daemon=True)
        sender_thread = threading.Thread(target=_run_sender, daemon=True)
        receiver_thread.start()
        sender_thread.start()

        while True:
            if not receiver_thread.is_alive() or not sender_thread.is_alive():
                return 1
            time.sleep(1)
    finally:
        _remove_pid()


def _spawn_daemon_process():
    cmd = _daemon_command()
    kwargs = {
        "cwd": str(APP_DIR),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if platform.system() == "Windows":
        flags = 0
        flags |= getattr(subprocess, "DETACHED_PROCESS", 0)
        flags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        flags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
        kwargs["creationflags"] = flags
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(cmd, **kwargs)


def _ensure_setup():
    if SETTINGS_PATH.exists():
        return True
    print("[!] settings.json not found. Launching setup wizard...")
    setup_wizard.main()
    setup_ok = SETTINGS_PATH.exists()
    if setup_ok:
        _prompt_add_to_path_after_setup()
    return setup_ok


def _ask_yes_no(prompt, default=True):
    try:
        answer = input(prompt).strip().lower()
    except EOFError:
        return default
    if not answer:
        return default
    return answer in {"y", "yes"}


def _normalize_path_entry(path_entry):
    cleaned = path_entry.strip().strip('"').strip("'")
    if not cleaned:
        return ""
    expanded = os.path.expanduser(os.path.expandvars(cleaned))
    return os.path.normcase(os.path.normpath(expanded))


def _path_contains(path_env, target_dir):
    separator = ";" if platform.system() == "Windows" else ":"
    normalized_target = _normalize_path_entry(str(target_dir))
    if not normalized_target:
        return False

    for entry in path_env.split(separator):
        if _normalize_path_entry(entry) == normalized_target:
            return True
    return False


def _launcher_path():
    if platform.system() == "Windows":
        return APP_DIR / "localcargo.cmd"
    return APP_DIR / "localcargo"


def _ensure_localcargo_launcher():
    launcher_path = _launcher_path()

    if platform.system() == "Windows":
        if getattr(sys, "frozen", False):
            target = f'"{Path(sys.executable).resolve()}" %*'
        else:
            target = f'"{Path(sys.executable).resolve()}" "{Path(__file__).resolve()}" %*'
        content = "@echo off\r\n" + target + "\r\n"
        launcher_path.write_text(content, encoding="utf-8")
        return launcher_path

    if getattr(sys, "frozen", False):
        target = f'exec "{Path(sys.executable).resolve()}" "$@"'
    else:
        target = f'exec "{Path(sys.executable).resolve()}" "{Path(__file__).resolve()}" "$@"'
    content = "#!/usr/bin/env bash\n" + target + "\n"
    launcher_path.write_text(content, encoding="utf-8")
    launcher_path.chmod(launcher_path.stat().st_mode | 0o111)
    return launcher_path


def _add_to_windows_user_path(target_dir):
    import winreg

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Environment",
        0,
        winreg.KEY_READ | winreg.KEY_WRITE,
    ) as key:
        try:
            current_path, reg_type = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            current_path, reg_type = "", winreg.REG_EXPAND_SZ

        if not isinstance(current_path, str):
            current_path = ""
        if _path_contains(current_path, target_dir):
            return False

        new_path = f"{current_path};{target_dir}" if current_path else str(target_dir)
        if reg_type not in {winreg.REG_SZ, winreg.REG_EXPAND_SZ}:
            reg_type = winreg.REG_EXPAND_SZ
        winreg.SetValueEx(key, "Path", 0, reg_type, new_path)

    process_path = os.environ.get("PATH", "")
    if not _path_contains(process_path, target_dir):
        os.environ["PATH"] = f"{target_dir};{process_path}" if process_path else str(
            target_dir
        )

    return True


def _unix_profile_file():
    shell_name = Path(os.environ.get("SHELL", "")).name.lower()
    home = Path.home()

    if shell_name == "zsh":
        return home / ".zshrc"
    if shell_name == "bash":
        if platform.system() == "Darwin":
            return home / ".bash_profile"
        return home / ".bashrc"
    return home / ".profile"


def _add_to_unix_shell_path(target_dir):
    profile_path = _unix_profile_file()
    marker_start = "# >>> LocalCargo PATH >>>"
    marker_end = "# <<< LocalCargo PATH <<<"
    export_line = f'export PATH="{target_dir}:$PATH"'
    block = f"{marker_start}\n{export_line}\n{marker_end}\n"

    if profile_path.exists():
        content = profile_path.read_text(encoding="utf-8")
    else:
        content = ""

    already_in_profile = marker_start in content or any(
        str(target_dir) in line and "PATH" in line for line in content.splitlines()
    )
    if already_in_profile:
        changed = False
    else:
        prefix = "" if not content or content.endswith("\n") else "\n"
        profile_path.write_text(content + prefix + block, encoding="utf-8")
        changed = True

    process_path = os.environ.get("PATH", "")
    if not _path_contains(process_path, target_dir):
        os.environ["PATH"] = f"{target_dir}:{process_path}" if process_path else str(
            target_dir
        )

    return changed, profile_path


def _enable_localcargo_terminal_command():
    target_dir = APP_DIR
    _ensure_localcargo_launcher()

    if platform.system() == "Windows":
        changed = _add_to_windows_user_path(target_dir)
        if changed:
            print(f"[+] Added to user PATH: {target_dir}")
        else:
            print("[*] LocalCargo path already exists in user PATH.")
    else:
        changed, profile_path = _add_to_unix_shell_path(target_dir)
        if changed:
            print(f"[+] Added PATH export to: {profile_path}")
        else:
            print(f"[*] PATH entry already exists in: {profile_path}")

    if shutil.which("localcargo"):
        print("[OK] `localcargo` command is available in this terminal.")
    else:
        print("[*] Open a new terminal and run: localcargo")


def _prompt_add_to_path_after_setup():
    if not sys.stdin.isatty():
        return

    should_add = _ask_yes_no(
        "[?] Add LocalCargo to PATH so you can run `localcargo` in terminal? (y/N): ",
        default=False,
    )
    if not should_add:
        return

    try:
        _enable_localcargo_terminal_command()
    except Exception as e:
        print(f"[!] Failed to configure PATH: {e}")


def start_services(ask_autostart=True):
    if not _ensure_setup():
        print("[!] Setup did not complete. Aborting start.")
        return 1

    running, pid = is_running()
    if running:
        print(f"[*] LocalCargo is already running (PID: {pid}).")
        return 0

    system = platform.system()

    if ask_autostart and not is_autostart_installed() and sys.stdin.isatty():
        should_enable_autostart = _ask_yes_no(
            "[?] Enable autostart on system boot? (Y/n): ", default=False
        )
        if should_enable_autostart:
            install_autostart()
            if system != "Windows":
                time.sleep(1)
                running, pid = is_running()
                if running:
                    print(f"[OK] LocalCargo started by OS service (PID: {pid}).")
                    return 0
                
    if is_autostart_installed():
        if system == "Darwin":
            subprocess.run(["launchctl", "load", str(_mac_plist_path())], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        elif system == "Linux":
            subprocess.run(["systemctl", "--user", "start", LINUX_SERVICE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    running, _ = is_running()
    if not running:
        _spawn_daemon_process()

    time.sleep(0.8)
    running, pid = is_running()
    if running:
        print(f"[OK] LocalCargo started in background (PID: {pid}).")
        return 0

    print("[!] Failed to start LocalCargo daemon.")
    return 1


def stop_services():
    system = platform.system()

    if is_autostart_installed():
        if system == "Darwin":
            subprocess.run(["launchctl", "unload", str(_mac_plist_path())], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            print("[*] macOS service suspended.")
        elif system == "Linux":
            subprocess.run(["systemctl", "--user", "stop", LINUX_SERVICE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            print("[*] Linux service suspended.")

    running, pid = is_running()
    if not running:
        print("[*] LocalCargo is not running.")
        return 0

    _stop_process_by_pid(pid)
    time.sleep(0.5)
    running, _ = is_running()
    if running:
        print("[!] Failed to stop LocalCargo daemon.")
        return 1

    print("[OK] LocalCargo stopped.")
    return 0


def remove_system():
    print("\n[!] Removing LocalCargo from the system...")
    
    # 1. Clean up autostart entries
    remove_autostart()
    
    # 2. Gracefully stop known services
    stop_services()

    print("[*] Hunting zombies and preparing to delete the source code directory...")
    print("[*] Terminal will close in 3 seconds. Goodbye!")

    system = platform.system()
    app_dir_str = str(APP_DIR)

    if system == "Windows":
        import tempfile
        temp_dir = tempfile.gettempdir()
        bat_path = os.path.join(temp_dir, "localcargo_nuke.bat")
        
        # Assassin BAT file for Windows
        bat_content = f"""@echo off
title LocalCargo Nuke Sequence
echo [*] Waiting for LocalCargo to exit...
timeout /T 2 /NOBREAK >nul
echo [*] Cleaning up zombie processes...
taskkill /F /IM {APP_NAME}.exe /T >nul 2>&1
taskkill /F /IM localcargo.exe /T >nul 2>&1
echo [*] Deleting source code directory: {app_dir_str}
rmdir /S /Q "{app_dir_str}"
echo [OK] All clean!
del "%~f0"
"""
        with open(bat_path, "w", encoding="utf-8") as f:
            f.write(bat_content)

        # Launch the assassin in a new, independent console
        subprocess.Popen(
            ["cmd.exe", "/c", bat_path],
            creationflags=subprocess.CREATE_NEW_CONSOLE | getattr(subprocess, "DETACHED_PROCESS", 0)
        )

    else:
        # Assassin BASH command for Mac and Linux
        # Writing [l]ocalcargo is a Unix trick. It prevents pkill from killing itself!
        script = f"""
        sleep 2
        pkill -9 -f "[l]ocalcargo" >/dev/null 2>&1
        rm -rf "{app_dir_str}"
        """
        # Launch the assassin detached from the current terminal (Daemonize) in the background
        subprocess.Popen(
            ["bash", "-c", script],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    # 3. Commit suicide immediately to release file locks!
    sys.exit(0)


def run_setup_only():
    stop_services()
    setup_wizard.main()
    if SETTINGS_PATH.exists():
        _prompt_add_to_path_after_setup()
    return 0


def interactive_menu():
    while True:
        print("\n" + "=" * 40)
        print(" LocalCargo Control Panel")
        print("=" * 40)
        print("  1. Start (run setup first if needed)")
        print("  2. Stop")
        print("  3. Remove from system")
        print("  4. Re-run setup")
        print("  5. Exit")

        choice = input("\n[?] Select action (1-5): ").strip()
        if choice == "1":
            start_services(ask_autostart=True)
        elif choice == "2":
            stop_services()
        elif choice == "3":
            remove_system()
        elif choice == "4":
            run_setup_only()
        elif choice == "5":
            return 0
        else:
            print("[!] Invalid choice.")


def print_usage():
    print("Usage: localcargo [start|stop|remove|setup|daemon|menu|status]")


def main():
    if len(sys.argv) == 1:
        return interactive_menu()

    command = sys.argv[1].lower()
    if command == "start":
        return start_services(ask_autostart=True)
    if command == "stop":
        return stop_services()
    if command == "remove":
        return remove_system()
    if command == "setup":
        return run_setup_only()
    if command == "daemon":
        return run_daemon()
    if command == "menu":
        return interactive_menu()
    if command == "status":
        running, pid = is_running()
        if running:
            print(f"[*] LocalCargo is running (PID: {pid}).")
        else:
            print("[*] LocalCargo is stopped.")
        return 0

    print_usage()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
