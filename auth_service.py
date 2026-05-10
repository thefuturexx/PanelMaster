import random
import secrets
import threading
import time
import requests
from werkzeug.security import check_password_hash, generate_password_hash


_RATE_LOCK = threading.Lock()
_RATE_STORE = {}
_OTP_LOCK = threading.Lock()
_OTP_STORE = {}


def ensure_auth_config(config, legacy_password=""):
    cfg = dict(config or {})
    changed = False

    if not str(cfg.get("auth_username", "")).strip():
        cfg["auth_username"] = "admin"
        changed = True

    if not str(cfg.get("auth_password_hash", "")).strip():
        seed = str(legacy_password or "").strip() or "admin123"
        cfg["auth_password_hash"] = generate_password_hash(seed)
        changed = True

    if "auth_2fa_enabled" not in cfg:
        cfg["auth_2fa_enabled"] = True
        changed = True
    if "auth_telegram_bot_token" not in cfg:
        cfg["auth_telegram_bot_token"] = ""
        changed = True
    if "auth_telegram_admin_id" not in cfg:
        cfg["auth_telegram_admin_id"] = ""
        changed = True
    if "auth_otp_ttl_seconds" not in cfg:
        cfg["auth_otp_ttl_seconds"] = 300
        changed = True

    return cfg, changed


def verify_login_credentials(config, username, password):
    cfg = config or {}
    expected_user = str(cfg.get("auth_username", "admin")).strip()
    saved_hash = str(cfg.get("auth_password_hash", "")).strip()
    user = str(username or "").strip()
    pwd = str(password or "")
    if not expected_user or not saved_hash:
        return False
    if user != expected_user:
        return False
    try:
        return check_password_hash(saved_hash, pwd)
    except Exception:
        return False


def resolve_auth_telegram_target(config):
    cfg = config or {}
    token = str(cfg.get("auth_telegram_bot_token", "")).strip()
    admin_id = str(cfg.get("auth_telegram_admin_id", "")).strip()
    if not token:
        token = str(cfg.get("backup_bot_token", "")).strip() or str(cfg.get("bot_token", "")).strip()
    if not admin_id:
        admin_id = str(cfg.get("backup_bot_admin_id", "")).strip()
    if not admin_id:
        admins = cfg.get("admin_ids", [])
        if isinstance(admins, list) and admins:
            admin_id = str(admins[0]).strip()
    return token, admin_id


def generate_otp_code():
    return f"{random.randint(0, 999999):06d}"


def send_otp_to_telegram(bot_token, admin_id, code, ttl_seconds=300):
    token = str(bot_token or "").strip()
    chat_id = str(admin_id or "").strip()
    if not token or not chat_id:
        return False, "telegram token/admin id missing"
    ttl = max(60, int(ttl_seconds or 300))
    text = (
        "PanelMaster Login OTP\n"
        f"Code: {code}\n"
        f"Expires in: {ttl // 60} min"
    )
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        res = requests.post(url, data={"chat_id": chat_id, "text": text}, timeout=20)
        if 200 <= res.status_code < 300:
            return True, "ok"
        return False, f"http {res.status_code}: {res.text[:180]}"
    except Exception as e:
        return False, str(e)


def create_otp_challenge(username, ttl_seconds=300):
    challenge_id = secrets.token_urlsafe(18)
    now = int(time.time())
    code = generate_otp_code()
    ttl = max(60, int(ttl_seconds or 300))
    with _OTP_LOCK:
        _OTP_STORE[challenge_id] = {
            "username": str(username or "").strip(),
            "code": code,
            "expires_ts": now + ttl,
            "created_ts": now
        }
    return challenge_id, code, now + ttl


def refresh_otp_challenge(challenge_id, ttl_seconds=300):
    cid = str(challenge_id or "").strip()
    if not cid:
        return None, None
    now = int(time.time())
    ttl = max(60, int(ttl_seconds or 300))
    code = generate_otp_code()
    with _OTP_LOCK:
        rec = _OTP_STORE.get(cid)
        if not rec:
            return None, None
        rec["code"] = code
        rec["expires_ts"] = now + ttl
        rec["created_ts"] = now
        _OTP_STORE[cid] = rec
    return code, now + ttl


def get_otp_challenge(challenge_id):
    cid = str(challenge_id or "").strip()
    if not cid:
        return None
    now = int(time.time())
    with _OTP_LOCK:
        rec = _OTP_STORE.get(cid)
        if not rec:
            return None
        if int(rec.get("expires_ts", 0) or 0) < now:
            _OTP_STORE.pop(cid, None)
            return None
        return dict(rec)


def verify_otp_challenge(challenge_id, code_input):
    cid = str(challenge_id or "").strip()
    inp = str(code_input or "").strip()
    if not cid or not inp:
        return False, None
    now = int(time.time())
    with _OTP_LOCK:
        rec = _OTP_STORE.get(cid)
        if not rec:
            return False, None
        if int(rec.get("expires_ts", 0) or 0) < now:
            _OTP_STORE.pop(cid, None)
            return False, None
        if str(rec.get("code", "")).strip() != inp:
            return False, dict(rec)
        username = str(rec.get("username", "")).strip()
        _OTP_STORE.pop(cid, None)
        return True, {"username": username}


def clear_otp_challenge(challenge_id):
    cid = str(challenge_id or "").strip()
    if not cid:
        return
    with _OTP_LOCK:
        _OTP_STORE.pop(cid, None)


def check_rate_limit(key, max_attempts=5, window_seconds=600, block_seconds=300):
    now = time.time()
    with _RATE_LOCK:
        rec = _RATE_STORE.get(key, {"fails": [], "blocked_until": 0.0})
        blocked_until = float(rec.get("blocked_until", 0.0) or 0.0)
        if blocked_until > now:
            return False, int(blocked_until - now)

        fails = [t for t in rec.get("fails", []) if now - t <= window_seconds]
        rec["fails"] = fails
        rec["blocked_until"] = 0.0
        _RATE_STORE[key] = rec
    return True, 0


def register_rate_failure(key, max_attempts=5, window_seconds=600, block_seconds=300):
    now = time.time()
    with _RATE_LOCK:
        rec = _RATE_STORE.get(key, {"fails": [], "blocked_until": 0.0})
        fails = [t for t in rec.get("fails", []) if now - t <= window_seconds]
        fails.append(now)
        rec["fails"] = fails
        if len(fails) >= max_attempts:
            rec["blocked_until"] = now + max(30, int(block_seconds))
            rec["fails"] = []
        _RATE_STORE[key] = rec


def register_rate_success(key):
    with _RATE_LOCK:
        if key in _RATE_STORE:
            _RATE_STORE.pop(key, None)
