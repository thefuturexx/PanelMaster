import hashlib
import hmac
import secrets
import threading
from datetime import datetime

from config import MASTER_API_KEY, load_config, save_config


_KEY_LOCK = threading.Lock()


def _now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _hash_api_key(raw_key):
    return hashlib.sha256(str(raw_key or "").encode("utf-8")).hexdigest()


def _clean_clients(cfg):
    clients = cfg.get("api_key_clients", [])
    if not isinstance(clients, list):
        clients = []
    out = []
    for c in clients:
        if not isinstance(c, dict):
            continue
        cid = str(c.get("id", "")).strip()
        kh = str(c.get("key_hash", "")).strip()
        if not cid or not kh:
            continue
        out.append(c)
    return out


def list_api_key_clients():
    cfg = load_config()
    clients = _clean_clients(cfg)
    masked = []
    for c in clients:
        masked.append({
            "id": str(c.get("id", "")).strip(),
            "name": str(c.get("name", "")).strip() or "unnamed",
            "enabled": bool(c.get("enabled", True)),
            "created_at": str(c.get("created_at", "")).strip(),
            "revoked_at": str(c.get("revoked_at", "")).strip(),
            "key_prefix": str(c.get("key_prefix", "")).strip(),
            "key_suffix": str(c.get("key_suffix", "")).strip(),
        })
    return masked


def create_api_key_client(name):
    raw_name = str(name or "").strip() or "client"
    cid = secrets.token_hex(6)
    raw_key = f"pmk_{secrets.token_urlsafe(32)}"
    key_hash = _hash_api_key(raw_key)
    now = _now_str()

    record = {
        "id": cid,
        "name": raw_name,
        "key_hash": key_hash,
        "enabled": True,
        "created_at": now,
        "revoked_at": "",
        "key_prefix": raw_key[:8],
        "key_suffix": raw_key[-6:],
    }
    with _KEY_LOCK:
        cfg = load_config()
        clients = _clean_clients(cfg)
        clients.append(record)
        cfg["api_key_clients"] = clients
        save_config(cfg)
    return {
        "id": cid,
        "name": raw_name,
        "api_key": raw_key,
        "created_at": now,
    }


def revoke_api_key_client(client_id):
    cid = str(client_id or "").strip()
    if not cid:
        return False
    changed = False
    with _KEY_LOCK:
        cfg = load_config()
        clients = _clean_clients(cfg)
        for c in clients:
            if str(c.get("id", "")).strip() == cid and bool(c.get("enabled", True)):
                c["enabled"] = False
                c["revoked_at"] = _now_str()
                changed = True
                break
        if changed:
            cfg["api_key_clients"] = clients
            save_config(cfg)
    return changed


def validate_api_key_value(api_key):
    raw = str(api_key or "").strip()
    if not raw:
        return False, {"source": "none"}
    if hmac.compare_digest(raw, str(MASTER_API_KEY or "").strip()):
        return True, {"source": "env_master"}

    raw_hash = _hash_api_key(raw)
    cfg = load_config()
    clients = _clean_clients(cfg)
    for c in clients:
        if not bool(c.get("enabled", True)):
            continue
        saved_hash = str(c.get("key_hash", "")).strip()
        if saved_hash and hmac.compare_digest(saved_hash, raw_hash):
            return True, {"source": "client", "id": str(c.get("id", "")).strip(), "name": str(c.get("name", "")).strip()}
    return False, {"source": "invalid"}
