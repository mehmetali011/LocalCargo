import os
import socket
from crypto_utils import get_decryptor
from utils import load_receiver_settings, tag_as_network_file

def _recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Socket closed before receiving expected metadata.")
        data.extend(chunk)
    return bytes(data)


def _parse_metadata(meta_data):
    parts = meta_data.split("<SPLITTER>")

    # Backward compatibility:
    # 2 fields -> file_name, file_size
    # 4 fields -> file_name, file_size, is_encrypted, iv_hex
    if len(parts) == 2:
        file_name, file_size = parts
        is_encrypted = "0"
        iv_hex = "NONE"
    elif len(parts) == 4:
        file_name, file_size, is_encrypted, iv_hex = parts
    else:
        raise ValueError("Invalid metadata format.")

    if is_encrypted not in {"0", "1"}:
        raise ValueError("Invalid encryption flag in metadata.")

    file_size = int(file_size)
    if file_size < 0:
        raise ValueError("Invalid file size in metadata.")

    return file_name, file_size, is_encrypted, iv_hex


def start_receiver():
    config = load_receiver_settings()
    port = config["PORT"]
    buffer_size = config["BUFFER_SIZE"]
    folder = config["FOLDER"]
    encryption_enabled = config["ENCRYPTION_ENABLED"]
    encryption_key = config["ENCRYPTION_KEY"]

    if not os.path.exists(folder):
        os.makedirs(folder)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen(5)

    print(f"[*] Receiver is now listening on port {port}... | Folder: {folder}")
    print(f"[*] Encryption enabled: {encryption_enabled}\n")

    while True:
        client_socket, _ = server_socket.accept()
        save_path = None
        download_complete = False
        try:
            meta_data = _recv_exact(client_socket, buffer_size).decode().strip()
            file_name, file_size, is_encrypted, iv_hex = _parse_metadata(meta_data)

            save_path = os.path.join(folder, file_name)
            print(f"\n[*] Downloading: {file_name} -> ({file_size} bytes)")

            decryptor = None
            if is_encrypted == "1":
                if not encryption_enabled:
                    raise ValueError(
                        "Encrypted payload received but ENCRYPTION_ENABLED is false."
                    )
                decryptor = get_decryptor(encryption_key, iv_hex)
                print("    [+] Encrypted transfer detected, decrypting with AES-256...")

            with open(save_path, "wb") as f:
                remaining_size = file_size
                while remaining_size > 0:
                    to_read = min(buffer_size, remaining_size)
                    chunk = client_socket.recv(to_read)
                    if not chunk:
                        break

                    if decryptor:
                        chunk = decryptor.update(chunk)

                    f.write(chunk)
                    remaining_size -= len(chunk)

                if remaining_size != 0:
                    raise ConnectionError(
                        "Transfer interrupted before expected file size was received."
                    )

                if decryptor:
                    final_chunk = decryptor.finalize()
                    if final_chunk:
                        f.write(final_chunk)

            tag_as_network_file(save_path)
            download_complete = True
            print(f"[OK] Downloading completed and network tag applied: {file_name}")

        except Exception as e:
            print(f"[!] Error: {e}")
            if save_path and os.path.exists(save_path) and not download_complete:
                try:
                    os.remove(save_path)
                    print("[*] Incomplete file removed.")
                except OSError:
                    pass
        finally:
            client_socket.close()


if __name__ == "__main__":
    start_receiver()
