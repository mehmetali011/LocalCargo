import base64
import hashlib
import json
import os
import platform
import random
import socket
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


def scan_network():
    """Scan local network for devices responding to Cargo discovery requests."""
    print("\n[*] Looking for Cargo hosts on the local network...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(1.0)

    try:
        sock.sendto(DISCOVERY_MAGIC, ("255.255.255.255", DISCOVERY_PORT))
    except Exception as e:
        print(f"[!] Broadcasting failed: {e}")
        sock.close()
        return []

    found_hosts = []
    try:
        while True:
            data, addr = sock.recvfrom(1024)
            if data.startswith(b"CARGO_HOST:"):
                hostname = data.split(b":", 1)[1].decode("utf-8")
                if hostname not in found_hosts and hostname != get_my_hostname():
                    found_hosts.append(hostname)
    except socket.timeout:
        pass
    finally:
        sock.close()

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


# Handshake and Setup
def run_initiator(target_host, folder, port, encryption_enabled):
    """Initiator side: generate key, wrap with PIN, complete handshake."""
    master_key = generate_encryption_key()
    pin = str(random.randint(1000, 9999))

    iv_hex, wrapped_key = wrap_master_key(master_key, pin)
    initiator_hostname = get_my_hostname()
    payload = f"{iv_hex}<SPLIT>{wrapped_key}<SPLIT>{initiator_hostname}".encode("utf-8")

    print(f"\n[!] Security Step: Enter this PIN on the other device: [ {pin} ]")
    print(f"[*] Waiting for {target_host} to enter the PIN...")

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
                save_settings(initiator_host, port, folder, encryption_enabled, master_key)
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


def prompt_for_folder_path(default_path):
    normalized_default = os.path.normpath(default_path)
    root = None

    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()

        if platform.system() == "Windows":
            root.attributes("-topmost", True)
        elif platform.system() == "Darwin":
            os.system(
                '''/usr/bin/osascript -e 'tell app "Finder" to set frontmost of process "Python" to true' '''
            )
            root.attributes("-topmost", True)

        print("\n[*] Please select the sync folder from the popup window...")
        selected_folder = filedialog.askdirectory(
            title="Select LocalCargo Sync Folder",
            initialdir=os.path.expanduser("~"),
        )

        if selected_folder:
            normalized_selected = os.path.normpath(selected_folder)
            print(f"[+] Folder selected: {normalized_selected}")
            return normalized_selected

        print("[-] No folder selected. Falling back to manual input.")
    except Exception:
        print("[*] GUI not available. Falling back to manual input.")
    finally:
        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass

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

    threading.Thread(target=discovery_listener, daemon=True).start()

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
        target_host = ""
        while not target_host:
            hosts = scan_network()
            if not hosts:
                print("  [-] No devices found. Scanning again in 1 second... (Ctrl+C to cancel)")
                time.sleep(1)
                continue

            print("\n  Discovered Devices:")
            for i, host in enumerate(hosts, start=1):
                print(f"  [{i}] {host}")

            choice = input(f"  [?] Select target device (1-{len(hosts)}): ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(hosts):
                target_host = hosts[int(choice) - 1]

        run_initiator(target_host, folder, port, encryption_enabled)

    elif role == "2":
        run_receiver(folder, port, encryption_enabled)
    else:
        print("[!] Invalid choice.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Setup aborted by user.")
        sys.exit(0)
