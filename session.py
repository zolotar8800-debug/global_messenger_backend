# session.py - управление сессиями (потокобезопасно)
import threading

sessions = {}
sessions_lock = threading.Lock()

def get_session(peer_ip):
    with sessions_lock:
        return sessions.get(peer_ip)

def set_session(peer_ip, data):
    with sessions_lock:
        sessions[peer_ip] = data

def update_session(peer_ip, **kwargs):
    with sessions_lock:
        if peer_ip in sessions:
            sessions[peer_ip].update(kwargs)

def delete_session(peer_ip):
    with sessions_lock:
        if peer_ip in sessions:
            del sessions[peer_ip]

def has_session(peer_ip):
    with sessions_lock:
        return peer_ip in sessions

def get_shared_key(peer_ip):
    with sessions_lock:
        session = sessions.get(peer_ip)
        return session.get("shared_key") if session else None

def is_in_progress(peer_ip):
    with sessions_lock:
        session = sessions.get(peer_ip)
        return session.get("in_progress", False) if session else False

def set_shared_key(peer_ip, key):
    with sessions_lock:
        if peer_ip in sessions:
            sessions[peer_ip]["shared_key"] = key