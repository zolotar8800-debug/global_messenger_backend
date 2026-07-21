#!/usr/bin/env python3
# main.py - точка входа, пароль опционален, улучшенный парсинг команд

import sys
import os
import threading
import argparse
import socket
from scapy.all import conf

from config import MAX_WORKERS, MAX_QUEUE_SIZE, DEFAULT_MODE
import crypto
import utils
import session
import network
import tasks


def auto_interface():
    """Автоматически определить активный сетевой интерфейс."""
    if conf.iface:
        return conf.iface
    try:
        import netifaces
        for iface in netifaces.interfaces():
            if iface != 'lo' and netifaces.ifaddresses(iface).get(netifaces.AF_INET):
                return iface
    except ImportError:
        pass
    return None


def start_dh_exchange(peer_ip: str):
    """Инициировать DH-обмен (только если пароль задан)."""
    if tasks.shared_password is None:
        print("[!] DH exchange requires a password. Please restart with -p <password>")
        return
    if not network.is_valid_ip(peer_ip):
        print(f"[!] Invalid IP address: {peer_ip}")
        return
    if session.is_in_progress(peer_ip):
        print(f"[!] DH exchange already in progress for {peer_ip}")
        return
    session.set_session(peer_ip, {
        "in_progress": True,
        "own_priv": None,
        "own_pub": None,
        "peer_pub": None,
        "shared_key": None,
        "verified": False
    })
    priv = crypto.DH_PARAMS.generate_private_key()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    payload = "DH_INIT:" + pub_bytes.decode('ascii')
    network.send_icmp_raw(peer_ip, payload)
    session.update_session(peer_ip, own_priv=priv, own_pub=pub, in_progress=True)
    print(f"[*] DH_INIT sent to {peer_ip}")


def main():
    parser = argparse.ArgumentParser(description="ICMP covert channel with optional authenticated DH and AES-GCM")
    parser.add_argument("-i", "--interface", help="Network interface (auto-detected if omitted)", default=None)
    parser.add_argument("-p", "--password", help="Shared secret for encryption (optional, plain mode if omitted)", default=None)
    parser.add_argument("--compress", action="store_true", help="Enable zlib compression")
    parser.add_argument("--max-workers", type=int, default=MAX_WORKERS, help="Worker threads")
    parser.add_argument("--max-queue", type=int, default=MAX_QUEUE_SIZE, help="Max queue size")
    args = parser.parse_args()

    # --- Обработка пароля ---
    if args.password:
        tasks.shared_password = args.password.encode('utf-8')
        print("[*] Encryption mode enabled (password provided).")
    else:
        tasks.shared_password = None
        print("[*] Running in plain mode (no encryption, no key exchange).")

    network.compress_enabled = args.compress

    # Переопределяем настройки пула, если переданы
    tasks.MAX_WORKERS = args.max_workers
    tasks.MAX_QUEUE_SIZE = args.max_queue

    # --- Определение интерфейса ---
    iface = args.interface
    if iface is None:
        iface = auto_interface()
        if iface:
            print(f"[*] Auto-detected interface: {iface}")
        else:
            print("[!] No interface detected, sniffing on all.")
            iface = None

    # Запускаем воркеры
    tasks.start_workers()
    print(f"[*] Started {tasks.MAX_WORKERS} worker threads, queue size limit {tasks.MAX_QUEUE_SIZE}")

    # Запускаем сниффер в отдельном потоке
    sniff_thread = threading.Thread(target=network.start_sniffer, args=(iface,), daemon=True)
    sniff_thread.start()
    print("[*] ICMP sniffer started. Commands:")
    print("  send <IP> <msg>                - send plain-text message")
    if tasks.shared_password is not None:
        print("  encrypt <IP> <msg>             - send encrypted message (requires key)")
        print("  key <IP>                       - start authenticated DH key exchange")
    else:
        print("  encrypt <IP> <msg>             - (disabled, no password)")
        print("  key <IP>                       - (disabled, no password)")
    print("  mode <plain|encrypted>         - set default mode for 'send'")
    print("  quit                           - exit")

    # Главный цикл команд
    while True:
        try:
            cmd_line = input("> ").strip()
            if not cmd_line:
                continue
            parts = cmd_line.split(maxsplit=2)  # разбиваем на 3 части: команда, IP, остаток
            if parts[0] == "quit":
                break
            elif parts[0] == "send" and len(parts) == 3:
                ip = parts[1]
                text = parts[2]
                network.send_icmp_text(ip, text, encrypt_it=(network.mode == "encrypted"))
            elif parts[0] == "encrypt" and len(parts) == 3:
                if tasks.shared_password is None:
                    print("[!] Encryption not available without password. Use -p <password> on startup.")
                else:
                    ip = parts[1]
                    text = parts[2]
                    if session.get_shared_key(ip) is None:
                        print(f"[!] No encryption key for {ip}. Run 'key' first.")
                    else:
                        network.send_icmp_text(ip, text, encrypt_it=True)
            elif parts[0] == "key" and len(parts) == 2:
                start_dh_exchange(parts[1])
            elif parts[0] == "mode" and len(parts) == 2:
                new_mode = parts[1].lower()
                if new_mode in ("plain", "encrypted"):
                    if new_mode == "encrypted" and tasks.shared_password is None:
                        print("[!] Cannot switch to encrypted mode without password. Use -p <password>.")
                    else:
                        network.mode = new_mode
                        print(f"[*] Default send mode set to {network.mode}")
                else:
                    print("[!] Invalid mode.")
            else:
                print("[?] Unknown command. Use: send <IP> <msg>, encrypt <IP> <msg>, key <IP>, mode <plain|encrypted>, quit")
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Interrupted. Exiting...")
            break

    tasks.stop_workers()
    print("[*] Exiting.")


if __name__ == "__main__":
    # Проверка прав
    if os.name == 'nt':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[-] Please run as Administrator.")
                sys.exit(1)
        except:
            pass
    else:
        if os.geteuid() != 0:
            print("[-] Requires root privileges. Run with sudo.")
            sys.exit(1)
    main()