#utils.py
import pyotp
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import base64

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


def encrypt_content_with_password(content, password):
    salt = get_random_bytes(16)
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(content.encode())
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()

def decrypt_content_with_password(encrypted_content, password):
    data = base64.b64decode(encrypted_content)
    salt, nonce, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]
    key = scrypt(password, salt, 32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_content = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_content.decode()

def verify_totp(user, totp_code):
    totp = pyotp.TOTP(user.totp_secret)
    return totp.verify(totp_code)