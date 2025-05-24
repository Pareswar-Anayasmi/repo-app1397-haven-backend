
from Crypto.Cipher import AES
import os
import logging

log = logging.getLogger(__name__)

def _pad_to_16_bytes(data):
    return data.ljust(16, b'\0')[:16]

def encrypt(plaintext: str, hex_key: str):
    cipher = AES.new(bytes.fromhex(hex_key), AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    padded_nonce = _pad_to_16_bytes(cipher.nonce)
    padded_tag = _pad_to_16_bytes(tag)
    combined = padded_nonce + padded_tag + ciphertext
    
    return combined

def decrypt(chiper: bytes, hex_key: str):
    nonce = chiper[:16]
    tag = chiper[16:32]
    ciphertext = chiper[32:]
    cipher = AES.new(bytes.fromhex(hex_key), AES.MODE_GCM, nonce=nonce.rstrip(b'\0'))
    plaintext = cipher.decrypt_and_verify(ciphertext, tag.rstrip(b'\0')).decode()
    return plaintext


def generate_secret_key():
    return os.urandom(32).hex() # 256-bit key
