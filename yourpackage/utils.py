#utils.py
import os

import pyotp
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import base64
import hashlib

def sign_content(content, user):
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

def simple_encrypt(plain_text):
    #return cipher_suite.encrypt(plain_text.encode('utf-8')).decode('utf-8')
    coded=encrypt_content_with_password(plain_text, os.getenv('ENCRYPTION_PASSWORD'))
    return coded

def simple_decrypt(cipher_text):
    #return cipher_suite.decrypt(cipher_text.encode('utf-8')).decode('utf-8')
    decoded=decrypt_content_with_password(cipher_text, os.getenv('ENCRYPTION_PASSWORD'))
    return decoded