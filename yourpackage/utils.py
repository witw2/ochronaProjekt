#utils.py
from cryptography.fernet import Fernet

# Generate a key for encryption
def generate_key():
    return Fernet.generate_key()

# Encrypt the content
def encrypt_content(content, key):
    f = Fernet(key)
    return f.encrypt(content.encode()).decode()

# Decrypt the content
def decrypt_content(content, key):
    f = Fernet(key)
    return f.decrypt(content.encode()).decode()

import hashlib

def sign_content(content, user):
    # Używamy funkcji hashującej do podpisania treści
    return hashlib.sha256(f'{content}{user.username}'.encode()).hexdigest()