"""
crypto_utils.py — AES-256-GCM encryption layer
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
from config import KEY

_aesgcm = AESGCM(KEY)

def encrypt(data: bytes) -> bytes:
    nonce = os.urandom(12)
    ciphertext = _aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt(data: bytes) -> bytes:
    nonce, ciphertext = data[:12], data[12:]
    return _aesgcm.decrypt(nonce, ciphertext, None)

def hex_preview(data: bytes, n: int = 20) -> str:
    return data[:n].hex() + ("..." if len(data) > n else "")
