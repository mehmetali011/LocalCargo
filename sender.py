import os
import time
from watchdog.observers import Observer
from utils import load_sender_settings
from cargo_handler import CargoHandler

def start_sender():
    config = load_sender_settings()
    TARGET_HOST = config["TARGET_HOST"]
    PORT = config["PORT"]
    BUFFER_SIZE = config["BUFFER_SIZE"]
    FOLDER = config["FOLDER"]
    ENCRYPTION_ENABLED = config["ENCRYPTION_ENABLED"]
    ENCRYPTION_KEY = config["ENCRYPTION_KEY"]

    if not os.path.exists(FOLDER):
        os.makedirs(FOLDER)

    event_handler = CargoHandler(
        TARGET_HOST,
        PORT,
        BUFFER_SIZE,
        ENCRYPTION_ENABLED,
        ENCRYPTION_KEY,
    )
    observer = Observer()
    observer.schedule(event_handler, FOLDER, recursive=False)
    observer.start()
    
    print(f"[*] Sender is now monitoring: {FOLDER}")
    print(f"[*] Target: {TARGET_HOST}:{PORT}\n")
    print(f"[*] Encryption enabled: {ENCRYPTION_ENABLED}\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n[!] Sender stopped by user.")
    
    observer.join()

if __name__ == "__main__":
    start_sender()
