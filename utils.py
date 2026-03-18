import json
import os
import sys
import base64
import binascii

# Marks a file with an invisible "Downloaded from Network" tag to prevent re-sending or re-processing.
def tag_as_network_file(filepath):
    try:
        if sys.platform == "win32":
            # Windows: Alternate Data Stream (ADS)
            with open(f"{filepath}:net_tag", "w") as f:
                f.write("1")
        else:
            # macOS / Linux: Extended Attributes (xattr)
            os.setxattr(filepath, b'user.net_tag', b'1')
    except Exception as e:
        print(f"[!] Meta veri yazılamadı: {e}")

# Checks if the file has the network tag to prevent re-sending or re-processing.
def is_network_file(filepath):
    try:
        if sys.platform == "win32":
            # Windows ADS kontrolü
            try:
                with open(f"{filepath}:net_tag", "r") as f:
                    return f.read() == "1"
            except FileNotFoundError:
                return False
        else:
            # macOS / Linux xattr kontrolü
            os.getxattr(filepath, b'user.net_tag')
            return True
    except Exception:
        return False

# Validates encryption-related settings and returns normalized values.
def _parse_encryption_settings(config):
    encryption_enabled = config.get("ENCRYPTION_ENABLED", False)
    encryption_key = config.get("ENCRYPTION_KEY", "")

    if not isinstance(encryption_enabled, bool):
        raise ValueError
    if not isinstance(encryption_key, str):
        raise ValueError
    encryption_key = encryption_key.strip()

    if encryption_enabled:
        if not encryption_key.strip():
            raise ValueError
        try:
            raw_key = base64.b64decode(encryption_key, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError
        if len(raw_key) != 32:
            raise ValueError

    return encryption_enabled, encryption_key

# Loads settings.json and returns sender-specific settings.
def load_sender_settings():
    try:
        with open("settings.json", "r", encoding="utf-8") as f:
            config = json.load(f)

        target_host = config["TARGET_HOST"]
        port = int(config["PORT"])
        buffer_size = int(config["BUFFER_SIZE"])
        folder = config["FOLDER"]

        # Fail fast on missing or invalid values.
        if (
            not isinstance(target_host, str)
            or not target_host.strip()
            or port <= 0
            or buffer_size <= 0
            or not isinstance(folder, str)
            or not folder.strip()
        ):
            raise ValueError

        encryption_enabled, encryption_key = _parse_encryption_settings(config)

        return {
            "TARGET_HOST": target_host,
            "PORT": port,
            "BUFFER_SIZE": buffer_size,
            "FOLDER": folder,
            "ENCRYPTION_ENABLED": encryption_enabled,
            "ENCRYPTION_KEY": encryption_key,
        }
    except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError, ValueError, OSError):
        print("[!] settings.json is corrupted please re-configure.")
        sys.exit(1)

# Loads settings.json and returns receiver-specific settings.
def load_receiver_settings():
    try:
        with open("settings.json", "r", encoding="utf-8") as f:
            config = json.load(f)

        port = int(config["PORT"])
        buffer_size = int(config["BUFFER_SIZE"])
        folder = config["FOLDER"]

        # Fail fast on missing or invalid values.
        if (
            port <= 0
            or buffer_size <= 0
            or not isinstance(folder, str)
            or not folder.strip()
        ):
            raise ValueError

        encryption_enabled, encryption_key = _parse_encryption_settings(config)

        return {
            "PORT": port,
            "BUFFER_SIZE": buffer_size,
            "FOLDER": folder,
            "ENCRYPTION_ENABLED": encryption_enabled,
            "ENCRYPTION_KEY": encryption_key,
        }
    except (FileNotFoundError, json.JSONDecodeError, KeyError, TypeError, ValueError, OSError):
        print("[!] settings.json is corrupted please re-configure.")
        sys.exit(1)
