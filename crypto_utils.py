import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_encryption_key():
    """Creates a random 256-bit key and returns it as a base64-encoded string."""
    return base64.b64encode(os.urandom(32)).decode('utf-8')

def get_encryptor(key_b64):
    """Creates an encryptor and a random IV (Initialization Vector) using the provided key."""
    key = base64.b64decode(key_b64)
    iv = os.urandom(16) # AES için 16 baytlık rastgele vektör
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    return cipher.encryptor(), iv.hex()

def get_decryptor(key_b64, iv_hex):
    """Creates a decryptor using the provided key and IV."""
    key = base64.b64decode(key_b64)
    iv = bytes.fromhex(iv_hex)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    return cipher.decryptor()