# network.py - отправка/приём ICMP, сниффер, парсинг
import sys
import binascii
import threading
import socket
from scapy.all import sr1, IP, ICMP, sniff

from config import DEFAULT_MODE
from crypto import encrypt_aes_gcm, decrypt_aes_gcm
from utils import compress, decompress, hash_bytes
from session import get_session, get_shared_key
import tasks

# Глобальные переменные, устанавливаемые из main
mode = DEFAULT_MODE
compress_enabled = False
last_seen = {}
last_seen_lock = threading.Lock()

def is_valid_ip(ip: str) -> bool:
    """Проверяет, является ли строка валидным IPv4-адресом."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def send_icmp_text(dst_ip: str, payload_str: str, encrypt_it: bool = False):
    """Send a text message via ICMP echo request."""
    if not is_valid_ip(dst_ip):
        print(f"[!] Invalid IP address: {dst_ip}")
        return

    if encrypt_it:
        if tasks.shared_password is None:
            print("[!] Cannot encrypt without password. Use -p <password> on startup.")
            return
        key = get_shared_key(dst_ip)
        if key is None:
            print(f"[!] No encryption key for {dst_ip}. Run key exchange first.")
            return
        plain_bytes = payload_str.encode('utf-8')
        if compress_enabled:
            plain_bytes = compress(plain_bytes)
        encrypted = encrypt_aes_gcm(plain_bytes, key)
        payload_hex = binascii.hexlify(encrypted).decode('ascii')
        final_payload = "ENC:" + payload_hex
    else:
        final_payload = "MSG:" + payload_str

    try:
        pkt = IP(dst=dst_ip) / ICMP() / final_payload
        sr1(pkt, timeout=2, verbose=False)
    except Exception as e:
        print(f"[!] Error sending packet: {e}")

def send_icmp_raw(dst_ip: str, payload: str):
    """Отправить произвольную строку в ICMP (используется для DH-ответов)."""
    if not is_valid_ip(dst_ip):
        print(f"[!] Invalid IP address: {dst_ip}")
        return
    try:
        pkt = IP(dst=dst_ip) / ICMP() / payload
        sr1(pkt, timeout=2, verbose=False)
    except Exception as e:
        print(f"[!] Error sending packet: {e}")

def handle_incoming_packet(pkt):
    """Callback для сниффера – обрабатывает входящие ICMP-пакеты."""
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

    # --- Обработка открытого текста ---
    if raw_load.startswith("MSG:"):
        msg = raw_load[4:]
        with last_seen_lock:
            key = (src_ip, hash_bytes(msg.encode()))
            if key in last_seen:
                return
            last_seen[key] = True
        print(f"\r[plain] {src_ip} -> {msg}\n> ", end="", flush=True)

    # --- Обработка зашифрованных сообщений ---
    elif raw_load.startswith("ENC:"):
        if tasks.shared_password is None:
            print(f"\r[!] Encrypted message from {src_ip} but no password set. Ignoring.\n> ", end="", flush=True)
            return
        hex_data = raw_load[4:]
        key = get_shared_key(src_ip)
        if key is None:
            print(f"\r[!] Encrypted message from {src_ip} but no session/key.\n> ", end="", flush=True)
            return
        try:
            enc_bytes = binascii.unhexlify(hex_data)
            decrypted = decrypt_aes_gcm(enc_bytes, key)
            if compress_enabled:
                decrypted = decompress(decrypted)
            dec_msg = decrypted.decode('utf-8')
            with last_seen_lock:
                key_tuple = (src_ip, hash_bytes(enc_bytes))
                if key_tuple in last_seen:
                    return
                last_seen[key_tuple] = True
            print(f"\r[encrypted] {src_ip} -> {dec_msg}\n> ", end="", flush=True)
        except Exception as e:
            print(f"\r[!] Decryption error from {src_ip}: {e}\n> ", end="", flush=True)

    # --- DH сообщения (только если пароль задан) ---
    elif raw_load.startswith("DH_INIT:"):
        if tasks.shared_password is None:
            print(f"\r[!] DH_INIT from {src_ip} ignored (no password).\n> ", end="", flush=True)
            return
        pub_pem = raw_load[8:]
        tasks.enqueue_task(tasks.handle_dh_init, src_ip, pub_pem)
        print("\r[*] DH_INIT from", src_ip, "- queued for processing.\n> ", end="", flush=True)

    elif raw_load.startswith("DH_RESP:"):
        if tasks.shared_password is None:
            print(f"\r[!] DH_RESP from {src_ip} ignored (no password).\n> ", end="", flush=True)
            return
        pub_pem = raw_load[8:]
        tasks.enqueue_task(tasks.handle_dh_resp, src_ip, pub_pem)
        print("\r[*] DH_RESP from", src_ip, "- queued for processing.\n> ", end="", flush=True)

    elif raw_load.startswith("DH_VERIFY:"):
        if tasks.shared_password is None:
            print(f"\r[!] DH_VERIFY from {src_ip} ignored (no password).\n> ", end="", flush=True)
            return
        hmac_hex = raw_load[10:]
        tasks.enqueue_task(tasks.handle_dh_verify, src_ip, hmac_hex)
        print("\r[*] DH_VERIFY from", src_ip, "- queued for verification.\n> ", end="", flush=True)

def start_sniffer(interface: str = None):
    """Запуск сниффера ICMP."""
    if interface:
        sniff(iface=interface, filter="icmp", prn=handle_incoming_packet, store=False)
    else:
        sniff(filter="icmp", prn=handle_incoming_packet, store=False)