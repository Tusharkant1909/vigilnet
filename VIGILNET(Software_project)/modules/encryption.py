from cryptography.fernet import Fernet
import base64
import hashlib

def encrypt_data(text, key):
    key_hash = hashlib.sha256(key.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_hash)
    fernet = Fernet(fernet_key)
    return fernet.encrypt(text.encode()).decode()

def decrypt_data(text, key):
    key_hash = hashlib.sha256(key.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_hash)
    fernet = Fernet(fernet_key)
    return fernet.decrypt(text.encode()).decode()