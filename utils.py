# utils.py - вспомогательные функции
import zlib
import hashlib

def compress(data: bytes) -> bytes:
    return zlib.compress(data)

def decompress(data: bytes) -> bytes:
    return zlib.decompress(data)

def hash_bytes(data: bytes) -> bytes:
    """MD5 hash for duplicate detection (fast, not cryptographic)."""
    return hashlib.md5(data).digest()