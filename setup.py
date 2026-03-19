import base64
import hashlib
import json
import os
import platform
import random
import shutil
import socket
import subprocess
import sys
import threading
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from crypto_utils import generate_encryption_key, get_decryptor, get_encryptor

# Settings
DISCOVERY_PORT = 54321
SETUP_TCP_PORT = 65433
DISCOVERY_MAGIC = b"CARGO_DISCOVER"


def get_my_hostname():
    """Return the device hostname with .local suffix for mDNS."""
    host = socket.gethostname()
    if not host.endswith(".local"):
        host += ".local"
    return host


def discovery_listener():
    """Answer discovery requests from other devices looking for Cargo hosts."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", DISCOVERY_PORT))
    my_hostname = get_my_hostname()

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if data == DISCOVERY_MAGIC:
                response = f"CARGO_HOST:{my_hostname}".encode("utf-8")
                sock.sendto(response, addr)
        except Exception:
            pass


def _candidate_broadcast_addresses():
    candidates = {"255.255.255.255"}
    local_ips = set()

    try:
        infos = socket.getaddrinfo(
            socket.gethostname(), None, family=socket.AF_INET, type=socket.SOCK_DGRAM
        )
        for info in infos:
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                local_ips.add(ip)
    except socket.gaierror:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            probe_ip = probe.getsockname()[0]
            if probe_ip and not probe_ip.startswith("127."):
                local_ips.add(probe_ip)
    except OSError:
        pass

    for ip in local_ips:
        parts = ip.split(".")
        if len(parts) == 4:
            parts[-1] = "255"
            candidates.add(".".join(parts))

    return sorted(candidates)


def scan_network():
    """Scan local network for devices responding to Cargo discovery requests."""
    print("\n[*] Looking for Cargo hosts on the local network...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.35)

    broadcast_targets = _candidate_broadcast_addresses()
    any_broadcast_sent = False

    def send_discovery_broadcasts():
        nonlocal any_broadcast_sent
        for target in broadcast_targets:
            try:
                sock.sendto(DISCOVERY_MAGIC, (target, DISCOVERY_PORT))
                any_broadcast_sent = True
            except OSError:
                continue

    found_hosts = []
    seen = set()
    my_hostname = get_my_hostname()
    try:
        for _ in range(3):
            send_discovery_broadcasts()
            round_deadline = time.time() + 1.0
            while time.time() < round_deadline:
                try:
                    data, addr = sock.recvfrom(1024)
                except socket.timeout:
                    break

                if not data.startswith(b"CARGO_HOST:"):
                    continue

                hostname = data.split(b":", 1)[1].decode("utf-8")
                host_ip = addr[0]
                host_key = (hostname, host_ip)
                if host_key in seen or hostname == my_hostname:
                    continue
                seen.add(host_key)
                found_hosts.append((hostname, host_ip))
    finally:
        sock.close()

    if not any_broadcast_sent:
        print("[!] Broadcasting failed on all network targets.")

    return found_hosts


def derive_pin_key(pin):
    """Create a 256-bit key from PIN using SHA-256."""
    return hashlib.sha256(pin.encode("utf-8")).digest()


def wrap_master_key(master_key_b64, pin):
    """Wrap Master Key using PIN-derived key. Returns IV and ciphertext."""
    pin_key = derive_pin_key(pin)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(pin_key), modes.CTR(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(master_key_b64.encode("utf-8")) + enc.finalize()
    return iv.hex(), base64.b64encode(ciphertext).decode("utf-8")


def unwrap_master_key(iv_hex, ciphertext_b64, pin):
    """Restore Master Key by decrypting with PIN-derived key."""
    pin_key = derive_pin_key(pin)
    iv = bytes.fromhex(iv_hex)
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = Cipher(algorithms.AES(pin_key), modes.CTR(iv), backend=default_backend())
    dec = cipher.decryptor()
    try:
        plaintext = dec.update(ciphertext) + dec.finalize()
        return plaintext.decode("utf-8")
    except Exception:
        return None


def pick_reachable_host(hostname, fallback_ip):
    try:
        socket.getaddrinfo(hostname, SETUP_TCP_PORT, type=socket.SOCK_STREAM)
        return hostname
    except socket.gaierror:
        return fallback_ip


# Handshake and Setup
def run_initiator(target_label, target_host, folder, port, encryption_enabled):
    """Initiator side: generate key, wrap with PIN, complete handshake."""
    master_key = generate_encryption_key()
    pin = str(random.randint(1000, 9999))

    iv_hex, wrapped_key = wrap_master_key(master_key, pin)
    initiator_hostname = get_my_hostname()
    payload = f"{iv_hex}<SPLIT>{wrapped_key}<SPLIT>{initiator_hostname}".encode("utf-8")

    print(f"\n[!] Security Step: Enter this PIN on the other device: [ {pin} ]")
    print(f"[*] Waiting for {target_label} to enter the PIN...")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(60.0)
            sock.connect((target_host, SETUP_TCP_PORT))
            sock.sendall(payload)

            handshake_req = sock.recv(4096)
            if not handshake_req:
                raise ConnectionError("Connection dropped.")

            iv_hex_recv, ciphertext_recv = handshake_req.split(b"<SPLIT>", 1)
            dec = get_decryptor(master_key, iv_hex_recv.decode("utf-8"))
            decrypted_msg = dec.update(base64.b64decode(ciphertext_recv)) + dec.finalize()

            if decrypted_msg.decode("utf-8") != "PING":
                print("[!] Handshake failed! Incorrect PIN or corrupted key.")
                return

            print("    [+] PING received, sending PONG...")
            enc, iv_hex_send = get_encryptor(master_key)
            pong_cipher = enc.update(b"PONG") + enc.finalize()
            response = f"{iv_hex_send}<SPLIT>{base64.b64encode(pong_cipher).decode('utf-8')}"
            sock.sendall(response.encode("utf-8"))

            print("\n[OK] HANDSHAKE SUCCESSFUL! Devices locked with secure key.")
            save_settings(target_host, port, folder, encryption_enabled, master_key)

    except Exception as e:
        print(f"\n[!] Setup failed (Timeout or Rejection): {e}")


def run_receiver(folder, port, encryption_enabled):
    """Receiver side: wait for initiator and complete handshake."""
    print("\n[*] Waiting for handshake... Please select this computer on the other device.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", SETUP_TCP_PORT))
        server.listen(1)

        client, addr = server.accept()
        initiator_ip = addr[0]

        try:
            payload = client.recv(4096).decode("utf-8")
            payload_parts = payload.split("<SPLIT>")
            if len(payload_parts) == 2:
                iv_hex, wrapped_key = payload_parts
                initiator_host = initiator_ip
            elif len(payload_parts) == 3:
                iv_hex, wrapped_key, initiator_host = payload_parts
                initiator_host = initiator_host.strip() or initiator_ip
            else:
                raise ValueError("Invalid setup payload format.")

            initiator_target = pick_reachable_host(initiator_host, initiator_ip)

            print(f"\n[+] {initiator_ip} sent a secure handshake request.")
            pin = input("    [?] Enter the 4-digit PIN from the other device: ").strip()

            master_key = unwrap_master_key(iv_hex, wrapped_key, pin)
            if not master_key or len(master_key) < 32:
                print("    [!] ERROR: Incorrect PIN or corrupted packet.")
                return

            print("    [+] PIN correct. Master Key extracted. Shaking hands...")
            enc, iv_hex_send = get_encryptor(master_key)
            ping_cipher = enc.update(b"PING") + enc.finalize()
            ping_payload = f"{iv_hex_send}<SPLIT>{base64.b64encode(ping_cipher).decode('utf-8')}"
            client.sendall(ping_payload.encode("utf-8"))

            handshake_resp = client.recv(4096)
            iv_hex_recv, ciphertext_recv = handshake_resp.split(b"<SPLIT>", 1)
            dec = get_decryptor(master_key, iv_hex_recv.decode("utf-8"))
            decrypted_msg = dec.update(base64.b64decode(ciphertext_recv)) + dec.finalize()

            if decrypted_msg.decode("utf-8") == "PONG":
                print("\n[OK] HANDSHAKE SUCCESSFUL! Devices locked with secure key.")
                save_settings(
                    initiator_target, port, folder, encryption_enabled, master_key
                )
            else:
                print("    [!] Handshake failed.")

        except Exception as e:
            print(f"\n[!] Setup failed: {e}")
        finally:
            client.close()


def save_settings(target_host, port, folder, encryption_enabled, encryption_key):
    settings = {
        "TARGET_HOST": target_host,
        "PORT": port,
        "BUFFER_SIZE": 4096,
        "FOLDER": folder,
        "ENCRYPTION_ENABLED": encryption_enabled,
        "ENCRYPTION_KEY": encryption_key,
    }
    with open("settings.json", "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4)
    print("[*] Settings successfully saved.")


def _pick_folder_macos_osascript(initial_dir):
    safe_initial_dir = initial_dir.replace("\\", "\\\\").replace('"', '\\"')
    command = [
        "/usr/bin/osascript",
        "-e",
        'tell application "Finder" to activate',
        "-e",
        f'set initialFolder to POSIX file "{safe_initial_dir}" as alias',
        "-e",
        "try",
        "-e",
        'set pickedFolder to POSIX path of (choose folder with prompt "Select LocalCargo Sync Folder" default location initialFolder)',
        "-e",
        "return pickedFolder",
        "-e",
        "on error number -128",
        "-e",
        'return ""',
        "-e",
        "end try",
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        stderr_text = result.stderr.strip() or "osascript failed"
        raise RuntimeError(stderr_text)
    return result.stdout.strip()


def _pick_folder_windows_tk(initial_dir):
    import tkinter as tk
    from tkinter import filedialog

    root = tk.Tk()
    try:
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        root.update_idletasks()
        selected_folder = filedialog.askdirectory(
            title="Select LocalCargo Sync Folder",
            initialdir=initial_dir,
            parent=root,
        )
        return selected_folder.strip() if selected_folder else ""
    finally:
        try:
            root.destroy()
        except Exception:
            pass


def _pick_folder_linux_gui(initial_dir):
    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if not has_display:
        raise RuntimeError("No DISPLAY/WAYLAND session detected")

    if shutil.which("zenity"):
        result = subprocess.run(
            [
                "zenity",
                "--file-selection",
                "--directory",
                "--title=Select LocalCargo Sync Folder",
                f"--filename={os.path.join(initial_dir, '')}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        if result.returncode == 1:
            return ""
        raise RuntimeError(result.stderr.strip() or "zenity failed")

    if shutil.which("kdialog"):
        result = subprocess.run(
            [
                "kdialog",
                "--getexistingdirectory",
                initial_dir,
                "Select LocalCargo Sync Folder",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        if result.returncode == 1:
            return ""
        raise RuntimeError(result.stderr.strip() or "kdialog failed")

    raise RuntimeError("No supported Linux folder picker found (zenity/kdialog)")


def prompt_for_folder_path(default_path):
    normalized_default = os.path.normpath(default_path)
    initial_dir = normalized_default if os.path.isdir(normalized_default) else os.path.expanduser("~")

    try:
        system = platform.system()
        print("\n[*] Please select the sync folder from the popup window...")

        if system == "Darwin":
            selected_folder = _pick_folder_macos_osascript(initial_dir)
        elif system == "Linux":
            selected_folder = _pick_folder_linux_gui(initial_dir)
        else:
            selected_folder = _pick_folder_windows_tk(initial_dir)

        if selected_folder:
            normalized_selected = os.path.normpath(selected_folder)
            print(f"[+] Folder selected: {normalized_selected}")
            return normalized_selected

        print("[-] No folder selected. Falling back to manual input.")
    except Exception as e:
        print(f"[*] GUI not available ({e}). Falling back to manual input.")

    manual_path = input(
        f"\n[?] Enter folder path manually (Default: {normalized_default}): "
    ).strip()
    return os.path.normpath(manual_path) if manual_path else normalized_default


# Main Menu
def main():
    print("=" * 55)
    print(" Local Cargo - Setup Wizard")
    print("=" * 55)
    print(f"[*] The mDNS address of this computer: {get_my_hostname()}\n")

    folder = prompt_for_folder_path("./Shared")
    port_input = input("[?] Port Number (Default: 65432): ").strip()
    port = int(port_input) if port_input.isdigit() else 65432

    enc_ans = input("[?] Enable encryption after setup? (Y/n): ").strip().lower()
    encryption_enabled = enc_ans != "n"

    print("\n[ PLEASE SELECT A PATH ]")
    print("  [1] Create a new secure connection with another device (Initiator)")
    print("  [2] Wait for a handshake from another device (Receiver/Listener)")

    role = input("\n  Your Choice (1/2): ").strip()

    # Auto-rescan every second instead of asking for manual retry.
    if role == "1":
        selected_host = None
        while not selected_host:
            hosts = scan_network()
            if not hosts:
                print("  [-] No devices found. Scanning again in 1 second... (Ctrl+C to cancel)")
                manual_target = input(
                    "  [?] Enter target IP/hostname manually (or press Enter to rescan): "
                ).strip()
                if manual_target:
                    selected_host = (manual_target, manual_target)
                    break
                time.sleep(1)
                continue

            print("\n  Discovered Devices:")
            for i, (host_name, host_ip) in enumerate(hosts, start=1):
                print(f"  [{i}] {host_name} ({host_ip})")

            choice = input(f"  [?] Select target device (1-{len(hosts)}): ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(hosts):
                selected_host = hosts[int(choice) - 1]

        target_name, target_ip = selected_host
        connect_host = pick_reachable_host(target_name, target_ip)
        if connect_host != target_name:
            print(f"[*] Hostname unresolved on this device, using IP: {target_ip}")

        run_initiator(target_name, connect_host, folder, port, encryption_enabled)

    elif role == "2":
        threading.Thread(target=discovery_listener, daemon=True).start()
        run_receiver(folder, port, encryption_enabled)
    else:
        print("[!] Invalid choice.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Setup aborted by user.")
        sys.exit(0)
