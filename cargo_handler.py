import os
import socket
import time
from watchdog.events import FileSystemEventHandler
from crypto_utils import get_encryptor
from utils import is_network_file


class CargoHandler(FileSystemEventHandler):
    def __init__(self, target_host, port, buffer_size, encryption_enabled, encryption_key):
        self.target_host = target_host
        self.port = port
        self.buffer_size = buffer_size
        self.encryption_enabled = encryption_enabled
        self.encryption_key = encryption_key

    def on_created(self, event):
        if event.is_directory:
            return

        filepath = event.src_path
        filename = os.path.basename(filepath)

        if filename.startswith(".") or filename.endswith(".tmp"):
            return

        if is_network_file(filepath):
            print(f"\n[*] '{filename}' is from network, skipping.")
            return

        print(f"\n[*] New file detected: {filename}")
        file_size = self._wait_until_file_ready(filepath)

        print(f"[*] Preparing to send: {filename} -> ({file_size} bytes)")
        self.send_file(filepath, filename, file_size)

    def _wait_until_file_ready(self, filepath):
        # Wait until file size is stable for two consecutive checks.
        file_size = -1
        stable_rounds = 0

        while stable_rounds < 2:
            try:
                current_size = os.path.getsize(filepath)
                if current_size == file_size:
                    stable_rounds += 1
                else:
                    stable_rounds = 0
                    file_size = current_size
                time.sleep(0.5)
            except OSError:
                stable_rounds = 0
                time.sleep(0.5)

        return file_size

    def send_file(self, filepath, filename, file_size):
        try:
            encryptor = None
            iv_hex = "NONE"
            is_encrypted = "0"

            if self.encryption_enabled:
                encryptor, iv_hex = get_encryptor(self.encryption_key)
                is_encrypted = "1"

            meta_data = f"{filename}<SPLITTER>{file_size}<SPLITTER>{is_encrypted}<SPLITTER>{iv_hex}"
            meta_bytes = meta_data.encode("utf-8")
            if len(meta_bytes) > self.buffer_size:
                raise ValueError(
                    "Metadata exceeds BUFFER_SIZE. Increase BUFFER_SIZE or shorten file name."
                )

            # Pad at byte level to guarantee exact BUFFER_SIZE payload.
            padded_meta_bytes = meta_bytes.ljust(self.buffer_size, b" ")

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect((self.target_host, self.port))
                client_socket.sendall(padded_meta_bytes)

                with open(filepath, "rb") as f:
                    while True:
                        chunk = f.read(self.buffer_size)
                        if not chunk:
                            break

                        if encryptor:
                            chunk = encryptor.update(chunk)

                        client_socket.sendall(chunk)

                if encryptor:
                    final_chunk = encryptor.finalize()
                    if final_chunk:
                        client_socket.sendall(final_chunk)

            print(f"[OK] Successfully sent (Encrypted: {bool(encryptor)}): {filename}")

        except ConnectionRefusedError:
            print(f"[!] Target is unreachable. Failed to send: {filename}")
        except Exception as e:
            print(f"[!] Error occurred while sending file: {e}")
