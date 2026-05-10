import os, json

SECRET_KEY = os.environ.get("PANEL_SECRET_KEY", "qito_super_secret_admin_key")
USERS_DB = "/root/qito_master/users_db.json"
NODES_LIST = "/root/qito_master/nodes_list.txt"
CONFIG_FILE = "/root/qito_master/config.json"
ADMIN_PASS = os.environ.get("PANEL_ADMIN_LEGACY_PASS", "admin123")
MASTER_API_KEY = os.environ.get("PANEL_MASTER_API_KEY", "My_Super_Secret_VPN_Key_2026")

_DEFAULT_SECRET_WARNED = False

def ensure_data_dirs():
    """Create required data directories before any read/write path is used."""
    for path in (USERS_DB, NODES_LIST, CONFIG_FILE):
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
    os.makedirs("/root/PanelMaster", exist_ok=True)
    os.makedirs("/root/PanelMaster/backups", exist_ok=True)

def safe_load_json(path, default=None):
    """Load JSON safely; if missing/corrupt, return default instead of crashing."""
    if default is None:
        default = {}
    try:
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return default
        with open(path, 'r') as f:
            data = json.load(f)
        return data if data is not None else default
    except Exception as e:
        print(f"[config] warning: failed to load JSON {path}: {e}")
        return default

def safe_save_json(path, data, indent=4):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=indent)
    os.replace(tmp, path)

def warn_default_secrets():
    """Warn once when production-dangerous default secrets are still in use."""
    global _DEFAULT_SECRET_WARNED
    if _DEFAULT_SECRET_WARNED:
        return
    warnings = []
    if SECRET_KEY == "qito_super_secret_admin_key":
        warnings.append("PANEL_SECRET_KEY")
    if ADMIN_PASS == "admin123":
        warnings.append("PANEL_ADMIN_LEGACY_PASS")
    if MASTER_API_KEY == "My_Super_Secret_VPN_Key_2026":
        warnings.append("PANEL_MASTER_API_KEY")
    if warnings:
        print("[security] WARNING: default secret(s) in use: " + ", ".join(warnings))
    _DEFAULT_SECRET_WARNED = True

def load_config():
    ensure_data_dirs()
    warn_default_secrets()
    config = {
        "interval": 12,
        "bot_token": "",
        "admin_ids": [],
        "mod_ids": [],
        "auth_username": "admin",
        "auth_password_hash": "",
        "auth_2fa_enabled": False,
        "auth_telegram_bot_token": "",
        "auth_telegram_admin_id": "",
        "auth_otp_ttl_seconds": 300,
        "api_key_clients": [],
        "disabled_nodes": [],
        "monitor_skip_nodes": [],
        "external_sync_url": "",
        "external_sync_api_key": "",
        "backup_bot_enabled": False,
        "backup_bot_token": "",
        "backup_bot_admin_id": "",
        "backup_bot_interval_hours": 1,
        "backup_bot_interval_minutes": 60,
        "backup_bot_last_sent_ts": 0,
        "backup_bot_last_update_id": 0
    }
    loaded = safe_load_json(CONFIG_FILE, {})
    if isinstance(loaded, dict):
        config.update(loaded)
    if not isinstance(config.get('admin_ids'), list): config['admin_ids'] = []
    if not isinstance(config.get('mod_ids'), list): config['mod_ids'] = []
    if not isinstance(config.get('disabled_nodes'), list): config['disabled_nodes'] = []
    if not isinstance(config.get('monitor_skip_nodes'), list): config['monitor_skip_nodes'] = []
    return config

def save_config(config):
    ensure_data_dirs()
    safe_save_json(CONFIG_FILE, config, indent=4)
