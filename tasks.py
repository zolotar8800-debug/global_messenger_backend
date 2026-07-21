# tasks.py - очередь задач, воркеры, обработчики DH-сообщений
import queue
import threading
import binascii
import sys
from cryptography.hazmat.primitives import serialization

from config import MAX_WORKERS, MAX_QUEUE_SIZE
from crypto import DH_PARAMS, derive_aes_key, compute_hmac
from session import (
    get_session, set_session, update_session, delete_session,
    has_session, get_shared_key, is_in_progress
)
import network

task_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
stop_event = threading.Event()

# Глобальный пароль (устанавливается из main, может быть None)
shared_password = None

# ---------------------------- DH-обработчики (вызываются из воркеров) ----------------------------
def handle_dh_init(peer_ip: str, pub_pem: str):
    """Обработка DH_INIT: генерация ключей, отправка DH_RESP."""
    if shared_password is None:
        print(f"[!] DH_INIT from {peer_ip} ignored: no password.")
        return
    try:
        peer_pub = serialization.load_pem_public_key(pub_pem.encode('ascii'), backend=default_backend())
    except Exception as e:
        print(f"[!] Failed to load peer public key from {peer_ip}: {e}")
        return

    our_priv = DH_PARAMS.generate_private_key()
    our_pub = our_priv.public_key()
    our_pub_bytes = our_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    shared_secret = our_priv.exchange(peer_pub)
    key = derive_aes_key(shared_secret, shared_password)

    set_session(peer_ip, {
        "in_progress": True,
        "own_priv": our_priv,
        "own_pub": our_pub,
        "peer_pub": peer_pub,
        "shared_secret": shared_secret,
        "shared_key": key,
        "verified": False
    })

    resp_payload = "DH_RESP:" + our_pub_bytes.decode('ascii')
    network.send_icmp_raw(peer_ip, resp_payload)
    print(f"[*] DH_RESP sent to {peer_ip}, waiting for verification...")

def handle_dh_resp(peer_ip: str, pub_pem: str):
    """Обработка DH_RESP: вычисление ключа, отправка DH_VERIFY."""
    if shared_password is None:
        print(f"[!] DH_RESP from {peer_ip} ignored: no password.")
        return
    session = get_session(peer_ip)
    if session is None or not session.get("in_progress"):
        print(f"[!] Unexpected DH_RESP from {peer_ip}, no exchange in progress.")
        return
    own_priv = session["own_priv"]
    own_pub = session["own_pub"]

    try:
        peer_pub = serialization.load_pem_public_key(pub_pem.encode('ascii'), backend=default_backend())
    except Exception as e:
        print(f"[!] Failed to load peer public key from {peer_ip}: {e}")
        return

    shared_secret = own_priv.exchange(peer_pub)
    key = derive_aes_key(shared_secret, shared_password)

    own_pub_bytes = own_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    our_hmac = compute_hmac(shared_secret, pub_pem.encode('ascii'), own_pub_bytes, shared_password)

    verify_payload = "DH_VERIFY:" + binascii.hexlify(our_hmac).decode('ascii')
    network.send_icmp_raw(peer_ip, verify_payload)

    update_session(peer_ip,
                   shared_secret=shared_secret,
                   shared_key=key,
                   peer_pub=peer_pub,
                   verified=True,
                   in_progress=False)
    print(f"[+] DH key exchange completed and authenticated for {peer_ip}")

def handle_dh_verify(peer_ip: str, hmac_hex: str):
    """Обработка DH_VERIFY: проверка HMAC, завершение обмена."""
    if shared_password is None:
        print(f"[!] DH_VERIFY from {peer_ip} ignored: no password.")
        return
    session = get_session(peer_ip)
    if session is None or not session.get("in_progress"):
        print(f"[!] Unexpected DH_VERIFY from {peer_ip}, no exchange in progress.")
        return

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
        delete_session(peer_ip)
        return

    update_session(peer_ip, verified=True, in_progress=False)
    print(f"[+] DH key exchange successfully completed and authenticated for {peer_ip}")

# ---------------------------- Очередь и воркеры ----------------------------
def worker():
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
    if task_queue.qsize() >= MAX_QUEUE_SIZE:
        print(f"[!] Task queue overflow ({MAX_QUEUE_SIZE} tasks). Dropping request from {args[0] if args else 'unknown'}")
        return
    task_queue.put((func, args, kwargs))

def start_workers():
    workers = []
    for _ in range(MAX_WORKERS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        workers.append(t)
    return workers

def stop_workers():
    stop_event.set()
    task_queue.join()