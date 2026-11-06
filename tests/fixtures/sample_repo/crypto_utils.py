from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import hashlib


def generate_rsa_key(bits: int = 2048):
    return RSA.generate(bits)


def encrypt_aes(key: bytes, data: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.encrypt(data)


def hash_data(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def encrypt_data(payload: str) -> str:
    key = b"\x00" * 16
    encrypted = encrypt_aes(key, payload.encode())
    return encrypted.hex()
