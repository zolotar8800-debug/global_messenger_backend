#!/usr/bin/env python3
"""
ICMP covert channel with authenticated DH key exchange,
AES-GCM encryption, optional compression, and thread pool
with queue overflow protection.
"""

import sys
import os
import binascii
import argparse
import hashlib
import hmac
import zlib
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from scapy.all import sr1, IP, ICMP, sniff
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend


# ---------------------------- CONFIGURATION ----------------------------
# DH parameters (2048-bit, RFC 3526 group 14)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
G = 2
DH_PARAMS = dh.DHParameterNumbers(P, G).parameters(default_backend())

# Thread pool settings
MAX_WORKERS = 8
MAX_QUEUE_SIZE = 100          # after this we drop new DH requests

# Global state
mode = "plain"                 # "plain" or "encrypted"
shared_password = None         # bytes, UTF-8 encoded
compress_enabled = False

# Session storage: key = peer_ip, value = dict with session data
sessions = {}
sessions_lock = threading.Lock()

# Duplicate detection cache (simple)
last_seen = {}
last_seen_lock = threading.Lock()

# Task queue for DH processing (to avoid blocking the sniffer)
task_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
stop_event = threading.Event()


# ---------------------------- HELPER FUNCTIONS ----------------------------
def derive_aes_key(shared_secret: bytes, password: bytes) -> bytes:
    """Derive 32-byte AES key from DH shared secret + password."""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_secret)
    digest.update(password)
    return digest.finalize()


def compute_hmac(shared_secret: bytes, peer_pub: bytes, own_pub: bytes, password: bytes) -> bytes:
    """Compute HMAC for mutual authentication during DH exchange."""
    h = hmac.new(shared_secret, digestmod=hashlib.sha256)
    h.update(peer_pub)
    h.update(own_pub)
    h.update(password)
    return h.digest()


def encrypt_aes_gcm(data: bytes, key: bytes) -> bytes:
    """Encrypt with AES-GCM, returns IV (12) + Tag (16) + Ciphertext."""
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ct


def decrypt_aes_gcm(enc_data: bytes, key: bytes) -> bytes:
    """Decrypt AES-GCM data: first 12 IV, next 16 tag, rest ciphertext."""
    iv = enc_data[:12]
    tag = enc_data[12:28]
    ct = enc_data[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()


def compress(data: bytes) -> bytes:
    return zlib.compress(data)


def decompress(data: bytes) -> bytes:
    return zlib.decompress(data)


def send_icmp_text(dst_ip: str, payload_str: str, encrypt_it: bool = False):
    """Send a text message via ICMP echo request."""
    if encrypt_it:
        with sessions_lock:
            session = sessions.get(dst_ip)
            if session is None or session.get("shared_key") is None:
                print(f"[!] No encryption key for {dst_ip}. Run key exchange first.")
                return
            key = session["shared_key"]
        plain_bytes = payload_str.encode('utf-8')
        if compress_enabled:
            plain_bytes = compress(plain_bytes)
        encrypted = encrypt_aes_gcm(plain_bytes, key)
        payload_hex = binascii.hexlify(encrypted).decode('ascii')
        final_payload = "ENC:" + payload_hex
    else:
        final_payload = "MSG:" + payload_str
    pkt = IP(dst=dst_ip) / ICMP() / final_payload
    sr1(pkt, timeout=2, verbose=False)


# ---------------------------- DH HANDLERS (called from worker threads) ----------------------------
def handle_dh_init(peer_ip: str, pub_pem: str):
    """Handle incoming DH_INIT: generate our key pair, send DH_RESP, wait for verification."""
    global shared_password
    # Load peer's public key
    try:
        peer_pub = serialization.load_pem_public_key(pub_pem.encode('ascii'), backend=default_backend())
    except Exception as e:
        print(f"[!] Failed to load peer public key from {peer_ip}: {e}")
        return

    # Generate our own key pair
    our_priv = DH_PARAMS.generate_private_key()
    our_pub = our_priv.public_key()
    our_pub_bytes = our_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Compute shared secret
    shared_secret = our_priv.exchange(peer_pub)
    key = derive_aes_key(shared_secret, shared_password)

    # Store session
    with sessions_lock:
        sessions[peer_ip] = {
            "in_progress": True,
            "own_priv": our_priv,
            "own_pub": our_pub,
            "peer_pub": peer_pub,
            "shared_secret": shared_secret,
            "shared_key": key,
            "verified": False
        }

    # Send DH_RESP with our public key
    resp_payload = "DH_RESP:" + our_pub_bytes.decode('ascii')
    pkt = IP(dst=peer_ip) / ICMP() / resp_payload
    sr1(pkt, timeout=2, verbose=False)
    print(f"[*] DH_RESP sent to {peer_ip}, waiting for verification...")


def handle_dh_resp(peer_ip: str, pub_pem: str):
    """Handle DH_RESP: compute shared secret, send DH_VERIFY."""
    global shared_password
    with sessions_lock:
        session = sessions.get(peer_ip)
        if session is None or not session.get("in_progress"):
            print(f"[!] Unexpected DH_RESP from {peer_ip}, no exchange in progress.")
            return
        own_priv = session["own_priv"]
        own_pub = session["own_pub"]

    # Load peer's public key
    try:
        peer_pub = serialization.load_pem_public_key(pub_pem.encode('ascii'), backend=default_backend())
    except Exception as e:
        print(f"[!] Failed to load peer public key from {peer_ip}: {e}")
        return

    shared_secret = own_priv.exchange(peer_pub)
    key = derive_aes_key(shared_secret, shared_password)

    # Compute HMAC to send
    own_pub_bytes = own_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    our_hmac = compute_hmac(shared_secret, pub_pem.encode('ascii'), own_pub_bytes, shared_password)

    # Send DH_VERIFY with our HMAC
    verify_payload = "DH_VERIFY:" + binascii.hexlify(our_hmac).decode('ascii')
    pkt = IP(dst=peer_ip) / ICMP() / verify_payload
    sr1(pkt, timeout=2, verbose=False)

    # Store shared key, mark as verified (we trust our own verification)
    with sessions_lock:
        session["shared_secret"] = shared_secret
        session["shared_key"] = key
        session["peer_pub"] = peer_pub
        session["verified"] = True
        session["in_progress"] = False
    print(f"[+] DH key exchange completed and authenticated for {peer_ip}")


def handle_dh_verify(peer_ip: str, hmac_hex: str):
    """Handle DH_VERIFY: verify peer's HMAC, complete exchange."""
    global shared_password
    with sessions_lock:
        session = sessions.get(peer_ip)
        if session is None or not session.get("in_progress"):
            print(f"[!] Unexpected DH_VERIFY from {peer_ip}, no exchange in progress.")
            return
        # We need to compute expected HMAC using our stored data
        own_pub_bytes = session["own_pub"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        peer_pub_bytes = session["peer_pub"].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        shared_secret = session["shared_secret"]

    expected = compute_hmac(shared_secret, peer_pub_bytes, own_pub_bytes, shared_password)
    received = binascii.unhexlify(hmac_hex)

    if not hmac.compare_digest(received, expected):
        print(f"[!] DH verification failed for {peer_ip} - possible MITM or wrong password.")
        with sessions_lock:
            del sessions[peer_ip]
        return

    # Verification OK
    with sessions_lock:
        session["verified"] = True
        session["in_progress"] = False
        # keep shared_key
    print(f"[+] DH key exchange successfully completed and authenticated for {peer_ip}")


# ---------------------------- TASK QUEUE AND WORKERS ----------------------------
def worker():
    """Worker thread that processes DH tasks from the queue."""
    while not stop_event.is_set():
        try:
            task = task_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        try:
            func, args, kwargs = task
            func(*args, **kwargs)
        except Exception as e:
            print(f"[!] Worker error: {e}")
        finally:
            task_queue.task_done()


def enqueue_task(func, *args, **kwargs):
    """Add a DH task to the queue, with overflow protection."""
    if task_queue.qsize() >= MAX_QUEUE_SIZE:
        print(f"[!] Task queue overflow ({MAX_QUEUE_SIZE} tasks). Dropping request from {args[0] if args else 'unknown'}")
        return
    task_queue.put((func, args, kwargs))


def start_workers():
    """Start the worker threads."""
    workers = []
    for _ in range(MAX_WORKERS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        workers.append(t)
    return workers


# ---------------------------- PACKET SNIFFER (CALLBACK) ----------------------------
def handle_incoming_packet(pkt):
    """Callback for sniffed packets."""
    global mode
    if ICMP not in pkt or pkt[ICMP].type not in (8, 0):
        return
    src_ip = pkt[IP].src
    print(f"\r[*] Ping from {src_ip} detected.\n> ", end="", flush=True)
    if not pkt[ICMP].load:
        return
    try:
        raw_load = pkt[ICMP].load.decode('utf-8', errors='ignore')
    except:
        return

    # Handle different message types
    if raw_load.startswith("MSG:"):
        msg = raw_load[4:]
        with last_seen_lock:
            key = (src_ip, hashlib.md5(msg.encode()).digest())
            if key in last_seen:
                return
            last_seen[key] = True
        print(f"\r[plain] {src_ip} -> {msg}\n> ", end="", flush=True)

    elif raw_load.startswith("ENC:"):
        hex_data = raw_load[4:]
        with sessions_lock:
            session = sessions.get(src_ip)
            if session is None:
                print(f"\r[!] Encrypted message from {src_ip} but no session. Run key exchange first.\n> ", end="", flush=True)
                return
            key = session.get("shared_key")
            if key is None:
                print(f"\r[!] No encryption key for {src_ip}.\n> ", end="", flush=True)
                return
        try:
            enc_bytes = binascii.unhexlify(hex_data)
            decrypted = decrypt_aes_gcm(enc_bytes, key)
            if compress_enabled:
                decrypted = decompress(decrypted)
            dec_msg = decrypted.decode('utf-8')
            with last_seen_lock:
                key_tuple = (src_ip, hashlib.md5(enc_bytes).digest())
                if key_tuple in last_seen:
                    return
                last_seen[key_tuple] = True
            print(f"\r[encrypted] {src_ip} -> {dec_msg}\n> ", end="", flush=True)
        except Exception as e:
            print(f"\r[!] Decryption error from {src_ip}: {e}\n> ", end="", flush=True)

    elif raw_load.startswith("DH_INIT:"):
        pub_pem = raw_load[8:]
        enqueue_task(handle_dh_init, src_ip, pub_pem)
        print("\r[*] DH_INIT from", src_ip, "- queued for processing.\n> ", end="", flush=True)

    elif raw_load.startswith("DH_RESP:"):
        pub_pem = raw_load[8:]
        enqueue_task(handle_dh_resp, src_ip, pub_pem)
        print("\r[*] DH_RESP from", src_ip, "- queued for processing.\n> ", end="", flush=True)

    elif raw_load.startswith("DH_VERIFY:"):
        hmac_hex = raw_load[10:]
        enqueue_task(handle_dh_verify, src_ip, hmac_hex)
        print("\r[*] DH_VERIFY from", src_ip, "- queued for verification.\n> ", end="", flush=True)


def start_sniffer(interface: str = None):
    """Start sniffing ICMP packets."""
    if interface:
        sniff(iface=interface, filter="icmp", prn=handle_incoming_packet, store=False)
    else:
        sniff(filter="icmp", prn=handle_incoming_packet, store=False)


# ---------------------------- COMMAND FUNCTIONS ----------------------------
def start_dh_exchange(peer_ip: str):
    """Initiate authenticated Diffie-Hellman key exchange with peer."""
    with sessions_lock:
        if peer_ip in sessions and sessions[peer_ip].get("in_progress"):
            print(f"[!] DH exchange already in progress for {peer_ip}")
            return
        # Create session entry
        sessions[peer_ip] = {"in_progress": True, "own_priv": None, "own_pub": None,
                             "peer_pub": None, "shared_key": None, "verified": False}
    # Generate own DH key pair
    priv = DH_PARAMS.generate_private_key()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Send DH_INIT
    payload = "DH_INIT:" + pub_bytes.decode('ascii')
    pkt = IP(dst=peer_ip) / ICMP() / payload
    sr1(pkt, timeout=2, verbose=False)
    with sessions_lock:
        sessions[peer_ip]["own_priv"] = priv
        sessions[peer_ip]["own_pub"] = pub
        sessions[peer_ip]["in_progress"] = True
    print(f"[*] DH_INIT sent to {peer_ip}")


# ---------------------------- MAIN ----------------------------
def main():
    global mode, shared_password, compress_enabled, MAX_WORKERS, MAX_QUEUE_SIZE

    parser = argparse.ArgumentParser(description="ICMP covert channel with authenticated DH and AES-GCM")
    parser.add_argument("-i", "--interface", help="Network interface", default=None)
    parser.add_argument("-p", "--password", required=True, help="Shared secret (password) for authentication")
    parser.add_argument("--compress", action="store_true", help="Enable zlib compression of payloads before encryption")
    parser.add_argument("--max-workers", type=int, default=MAX_WORKERS, help="Number of worker threads for DH processing")
    parser.add_argument("--max-queue", type=int, default=MAX_QUEUE_SIZE, help="Max queue size before dropping DH requests")
    args = parser.parse_args()

    shared_password = args.password.encode('utf-8')
    compress_enabled = args.compress

    # Override globals if provided
    MAX_WORKERS = args.max_workers
    MAX_QUEUE_SIZE = args.max_queue

    # Start worker threads
    start_workers()
    print(f"[*] Started {MAX_WORKERS} worker threads, queue size limit {MAX_QUEUE_SIZE}")

    # Start sniffer thread
    sniff_thread = threading.Thread(target=start_sniffer, args=(args.interface,), daemon=True)
    sniff_thread.start()
    print("[*] ICMP sniffer started. Commands:")
    print("  send <IP> <msg>                - send plain-text message")
    print("  encrypt <IP> <msg>             - send encrypted message (requires key)")
    print("  key <IP>                       - start authenticated DH key exchange")
    print("  mode <plain|encrypted>         - set default mode for 'send'")
    print("  quit                           - exit")

    # Main command loop
    while True:
        try:
            cmd_line = input("> ").strip()
            if not cmd_line:
                continue
            parts = cmd_line.split(maxsplit=2)
            if parts[0] == "quit":
                break
            elif parts[0] == "send" and len(parts) == 3:
                ip, text = parts[1], parts[2]
                send_icmp_text(ip, text, encrypt_it=(mode == "encrypted"))
            elif parts[0] == "encrypt" and len(parts) == 3:
                ip, text = parts[1], parts[2]
                with sessions_lock:
                    if ip not in sessions or sessions[ip].get("shared_key") is None:
                        print(f"[!] No encryption key for {ip}. Run 'key' first.")
                    else:
                        send_icmp_text(ip, text, encrypt_it=True)
            elif parts[0] == "key" and len(parts) == 2:
                ip = parts[1]
                start_dh_exchange(ip)
            elif parts[0] == "mode" and len(parts) == 2:
                new_mode = parts[1].lower()
                if new_mode in ("plain", "encrypted"):
                    if new_mode == "encrypted":
                        # Warn if no keys exist, but allow
                        with sessions_lock:
                            if not any(s.get("shared_key") for s in sessions.values()):
                                print("[!] No keys established yet, but you can still switch.")
                    mode = new_mode
                    print(f"[*] Default send mode set to {mode}")
                else:
                    print("[!] Invalid mode. Use 'plain' or 'encrypted'")
            else:
                print("[?] Unknown command. Use: send, encrypt, key, mode, quit")
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Interrupted. Exiting...")
            break

    # Signal workers to stop and wait for queue to empty (optional)
    stop_event.set()
    print("[*] Waiting for pending tasks to finish...")
    task_queue.join()
    print("[*] Exiting.")


if __name__ == "__main__":
    import ctypes
    if os.name == 'nt':
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[-] Please run as Administrator.")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("[-] Requires root privileges. Run with sudo.")
            sys.exit(1)
    main()