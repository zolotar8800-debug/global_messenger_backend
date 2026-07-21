# crypto.py - криптографические функции

import os
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from config import P, G

DH_PARAMS = dh.DHParameterNumbers(P, G).parameters(default_backend())


def derive_aes_key(shared_secret: bytes, password: bytes) -> bytes:
    """
    Derive 32-byte AES key from DH shared secret + password using HKDF-SHA256.
    Password is used as salt for additional security.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=password,          # пароль как соль
        info=b"ICMP_CHANNEL_AES_KEY_V1",
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)


def compute_hmac(shared_secret: bytes, peer_pub: bytes, own_pub: bytes, password: bytes) -> bytes:
    """
    Compute HMAC for mutual authentication during DH exchange.
    """
    h = hmac.new(shared_secret, digestmod=hashlib.sha256)
    h.update(peer_pub)
    h.update(own_pub)
    h.update(password)
    return h.digest()


def encrypt_aes_gcm(data: bytes, key: bytes) -> bytes:
    """
    Encrypt with AES-GCM. Returns: IV (12 bytes) + Tag (16 bytes) + Ciphertext
    """
    iv = os.urandom(12)
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext


def decrypt_aes_gcm(enc_data: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-GCM data. Format: IV (12) + Tag (16) + Ciphertext
    """
    iv = enc_data[:12]
    tag = enc_data[12:28]
    ciphertext = enc_data[28:]
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()