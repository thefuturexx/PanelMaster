from flask import Flask, render_template, request, redirect, session, url_for, send_file, jsonify
import json, os, re, secrets, subprocess, urllib.parse, base64, threading, time, requests, shlex, shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

from config import SECRET_KEY, USERS_DB, NODES_LIST, CONFIG_FILE, ADMIN_PASS, MASTER_API_KEY, load_config, save_config, ensure_data_dirs, safe_load_json, safe_save_json
from utils import get_nodes, get_all_servers, check_live_status, check_live_status_for_node, db_lock, AUTO_GROUPS_FILE, NODES_DB, make_db_key, get_display_name, find_db_key
from core_auto import load_auto_groups, save_auto_groups

from core_engine import execute_ssh_bg, get_safe_delete_cmd, get_safe_add_out_cmd
from core_monitor import start_background_monitor, get_monitor_status
from core_node import add_keys, toggle_key, delete_key, bulk_delete_keys, renew_key, edit_key, rebalance_auto_node
from core_ip import get_active_ips
from core_backup import (
    list_backups,
    safe_backup_path,
    create_node_backup_snapshot,
    create_full_backup_snapshot,
    read_backup_json,
)
from core_backup_bot import send_backup_to_telegram, start_backup_scheduler
from auth_service import (
    ensure_auth_config,
    verify_login_credentials,
    resolve_auth_telegram_target,
    send_otp_to_telegram,
    create_otp_challenge,
    refresh_otp_challenge,
    get_otp_challenge,
    verify_otp_challenge,
    clear_otp_challenge,
    check_rate_limit,
    register_rate_failure,
    register_rate_success,
)
from core_security_keys import (
    list_api_key_clients,
    create_api_key_client,
    revoke_api_key_client,
)

# 🚀 API Blueprint ကို လှမ်းခေါ်ခြင်း
from core_api import api_bp

app = Flask(__name__)
app.secret_key = SECRET_KEY
ensure_data_dirs()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = str(os.environ.get("SESSION_COOKIE_SECURE", "0")).strip() in ("1", "true", "True")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
BACKUP_DIR = "/root/PanelMaster/backups"
ACTIVITY_LOG_FILE = os.path.join(BACKUP_DIR, "dashboard_activity_log.json")
ACTIVITY_LOG_LOCK = threading.Lock()
_SYNC_NEW_SERVER_STATUS = {
    "last_attempt_at": "",
    "last_ok_at": "",
    "last_group_id": "",
    "last_node_id": "",
    "last_version": "",
    "last_status": "idle",
    "last_url": "",
    "last_http_code": 0,
    "last_error": "",
    "last_body_preview": ""
}
_SYNC_NEW_SERVER_STATUS_LOCK = threading.Lock()


def _set_sync_new_server_status(**kwargs):
    with _SYNC_NEW_SERVER_STATUS_LOCK:
        _SYNC_NEW_SERVER_STATUS.update(kwargs)


def _get_sync_new_server_status():
    with _SYNC_NEW_SERVER_STATUS_LOCK:
        return dict(_SYNC_NEW_SERVER_STATUS)

if not os.path.exists(BACKUP_DIR): 
    os.makedirs(BACKUP_DIR)

# 🚀 API Routes များကို Flask ထဲသို့ ပေါင်းထည့်ခြင်း
app.register_blueprint(api_bp)

start_background_monitor()


def _get_expected_origin():
    proto = str(request.headers.get("X-Forwarded-Proto", "")).strip().split(",")[0].strip()
    if not proto:
        proto = "https" if request.is_secure else "http"
    host = str(request.host or "").strip()
    return f"{proto}://{host}"


def _same_origin_ok():
    expected = _get_expected_origin()
    origin = str(request.headers.get("Origin", "")).strip()
    referer = str(request.headers.get("Referer", "")).strip()
    if origin:
        return origin.startswith(expected)
    if referer:
        return referer.startswith(expected)
    return True


def _get_or_create_csrf_token():
    tok = str(session.get("_csrf_token", "")).strip()
    if not tok:
        tok = secrets.token_urlsafe(24)
        session["_csrf_token"] = tok
    return tok


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": _get_or_create_csrf_token()}


@app.before_request
def enforce_https_and_csrf():
    force_https = str(os.environ.get("FORCE_HTTPS", "0")).strip() in ("1", "true", "True")
    if force_https:
        is_https = request.is_secure or str(request.headers.get("X-Forwarded-Proto", "")).startswith("https")
        host_l = str(request.host or "").lower()
        if not is_https and "localhost" not in host_l and "127.0.0.1" not in host_l:
            return redirect(request.url.replace("http://", "https://", 1), code=301)

    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    if request.path.startswith("/api/") or request.path.startswith("/conf/"):
        return

    if not _same_origin_ok():
        return "Forbidden (origin check failed).", 403

    csrf_expected = _get_or_create_csrf_token()
    csrf_sent = (
        str(request.form.get("_csrf_token", "")).strip()
        or str(request.headers.get("X-CSRF-Token", "")).strip()
    )
    if not csrf_sent or csrf_sent != csrf_expected:
        return "Forbidden (csrf check failed).", 403


@app.after_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
    if request.is_secure or str(request.headers.get("X-Forwarded-Proto", "")).startswith("https"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    csrf_token = _get_or_create_csrf_token()
    response.set_cookie(
        "csrf_token",
        csrf_token,
        secure=app.config.get("SESSION_COOKIE_SECURE", False),
        httponly=False,
        samesite="Lax",
        path="/"
    )

    ctype = str(response.headers.get("Content-Type", "")).lower()
    if "text/html" in ctype:
        body = response.get_data(as_text=True)
        if body and "</body>" in body:
            inject_js = """
<script>
(function(){
  function getCookie(name){
    var m=document.cookie.match(new RegExp('(?:^|; )'+name.replace(/[.$?*|{}()\\[\\]\\\\\\/\\+^]/g,'\\\\$&')+'=([^;]*)'));
    return m?decodeURIComponent(m[1]):'';
  }
  function applyCsrf(){
    var t=getCookie('csrf_token');
    if(!t){return;}
    var forms=document.querySelectorAll('form');
    for(var i=0;i<forms.length;i++){
      if(forms[i].querySelector('input[name="_csrf_token"]')){continue;}
      var input=document.createElement('input');
      input.type='hidden';
      input.name='_csrf_token';
      input.value=t;
      forms[i].appendChild(input);
    }
  }
  if(document.readyState==='loading'){
    document.addEventListener('DOMContentLoaded', applyCsrf);
  }else{
    applyCsrf();
  }
})();
</script>
"""
            response.set_data(body.replace("</body>", inject_js + "\n</body>"))
    return response

@app.before_request
def check_auth():
    # Blueprint API routes protect themselves with x-api-key. UI-owned /api/*
    # routes should still require a logged-in session unless explicitly allowed.
    if request.endpoint and str(request.endpoint).startswith('api_bp.'):
        return
    if request.path.startswith('/conf/'):
        return
    allowed_ui_endpoints = ['login', 'login_otp', 'resend_login_otp', 'static']
    if request.endpoint not in allowed_ui_endpoints and not session.get('logged_in'): 
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    cfg = load_config()
    cfg, changed = ensure_auth_config(cfg, legacy_password=ADMIN_PASS)
    if changed:
        save_config(cfg)

    error = ""
    is_2fa_enabled = bool(cfg.get("auth_2fa_enabled", True))
    login_ip = str(request.headers.get("X-Forwarded-For", request.remote_addr or "")).split(",")[0].strip() or "unknown"
    login_rate_key = f"auth-login:{login_ip}"

    if request.method == 'POST':
        allowed, wait_seconds = check_rate_limit(login_rate_key, max_attempts=6, window_seconds=600, block_seconds=300)
        if not allowed:
            error = f"Too many attempts. Try again in {wait_seconds}s."
            log_activity("Auth Login Blocked", f"ip={login_ip} wait={wait_seconds}s", "warning")
            return render_template('login.html', error=error)

        username = str(request.form.get('username', '')).strip()
        password = str(request.form.get('password', '')).strip()
        user_rate_key = f"auth-login-user:{username.lower() or 'unknown'}"
        allowed_user, wait_user = check_rate_limit(user_rate_key, max_attempts=6, window_seconds=600, block_seconds=300)
        if not allowed_user:
            error = f"Too many attempts. Try again in {wait_user}s."
            log_activity("Auth Login Blocked", f"user={username or '-'} wait={wait_user}s", "warning")
            return render_template('login.html', error=error)

        if not verify_login_credentials(cfg, username, password):
            register_rate_failure(login_rate_key, max_attempts=6, window_seconds=600, block_seconds=300)
            register_rate_failure(user_rate_key, max_attempts=6, window_seconds=600, block_seconds=300)
            error = "Invalid username or password."
            log_activity("Auth Login Failed", f"user={username or '-'} ip={login_ip}", "warning")
            return render_template('login.html', error=error)

        register_rate_success(login_rate_key)
        register_rate_success(user_rate_key)
        if not is_2fa_enabled:
            session.clear()
            session['logged_in'] = True
            session.permanent = True
            log_activity("Auth Login Success", f"user={username or '-'} no_2fa=true", "success")
            return redirect(url_for('dashboard'))

        token, admin_id = resolve_auth_telegram_target(cfg)
        if not token or not admin_id:
            session['logged_in'] = True
            session['auth_user'] = username
            log_activity("Auth Login Success", f"user={username or '-'} 2fa_skipped=telegram_not_configured", "success")
            return redirect(url_for('dashboard'))

        ttl_seconds = int(cfg.get("auth_otp_ttl_seconds", 300) or 300)
        challenge_id, code, expires_ts = create_otp_challenge(username, ttl_seconds=ttl_seconds)
        ok, msg = send_otp_to_telegram(token, admin_id, code, ttl_seconds=ttl_seconds)
        if not ok:
            error = f"Failed to send OTP: {msg}"
            clear_otp_challenge(challenge_id)
            log_activity("Auth OTP Send Failed", msg[:150], "error")
            return render_template('login.html', error=error)

        session.clear()
        session['otp_pending'] = True
        session['otp_challenge_id'] = challenge_id
        session['otp_user'] = username
        session['otp_expires_ts'] = int(expires_ts)
        session['otp_sent_ts'] = int(time.time())
        log_activity("Auth OTP Sent", f"user={username or '-'} ttl={ttl_seconds}s", "info")
        return redirect(url_for('login_otp'))
    return render_template('login.html', error=error)


@app.route('/login/otp', methods=['GET', 'POST'])
def login_otp():
    if not session.get('otp_pending'):
        return redirect(url_for('login'))

    _ = load_config()
    error = ""
    now_ts = int(time.time())
    expires_ts = int(session.get('otp_expires_ts', 0) or 0)
    challenge_id = str(session.get('otp_challenge_id', '')).strip()
    login_user = str(session.get('otp_user', '')).strip()
    if not challenge_id:
        session.clear()
        return redirect(url_for('login'))
    rec = get_otp_challenge(challenge_id)
    if not rec:
        session.clear()
        return redirect(url_for('login'))
    expires_ts = int(rec.get('expires_ts', expires_ts) or expires_ts)
    if expires_ts and now_ts > expires_ts:
        clear_otp_challenge(challenge_id)
        session.clear()
        return redirect(url_for('login'))

    otp_ip = str(request.headers.get("X-Forwarded-For", request.remote_addr or "")).split(",")[0].strip() or "unknown"
    otp_rate_key = f"auth-otp:{otp_ip}"

    if request.method == 'POST':
        allowed, wait_seconds = check_rate_limit(otp_rate_key, max_attempts=8, window_seconds=600, block_seconds=300)
        if not allowed:
            error = f"Too many OTP attempts. Try again in {wait_seconds}s."
            log_activity("Auth OTP Blocked", f"user={login_user or '-'} ip={otp_ip} wait={wait_seconds}s", "warning")
            return render_template('login_otp.html', error=error, expires_ts=expires_ts)

        code_input = str(request.form.get('otp_code', '')).strip()
        ok_verify, result = verify_otp_challenge(challenge_id, code_input)
        if not ok_verify:
            register_rate_failure(otp_rate_key, max_attempts=8, window_seconds=600, block_seconds=300)
            error = "Invalid OTP code."
            log_activity("Auth OTP Failed", f"user={login_user or '-'} ip={otp_ip}", "warning")
            return render_template('login_otp.html', error=error, expires_ts=expires_ts)

        register_rate_success(otp_rate_key)
        final_user = str((result or {}).get("username", login_user)).strip()
        session.clear()
        session['logged_in'] = True
        session['auth_user'] = final_user
        session.permanent = True
        log_activity("Auth Login Success", f"user={final_user or '-'} with_2fa=true", "success")
        return redirect(url_for('dashboard'))

    return render_template('login_otp.html', error=error, expires_ts=expires_ts)


@app.route('/login/otp/resend', methods=['POST'])
def resend_login_otp():
    if not session.get('otp_pending'):
        return redirect(url_for('login'))
    cfg = load_config()
    token, admin_id = resolve_auth_telegram_target(cfg)
    if not token or not admin_id:
        return redirect(url_for('login'))

    challenge_id = str(session.get('otp_challenge_id', '')).strip()
    if not challenge_id:
        return redirect(url_for('login'))

    ttl_seconds = int(cfg.get("auth_otp_ttl_seconds", 300) or 300)
    code, expires_ts = refresh_otp_challenge(challenge_id, ttl_seconds=ttl_seconds)
    if not code:
        clear_otp_challenge(challenge_id)
        session.clear()
        return redirect(url_for('login'))

    ok, _ = send_otp_to_telegram(token, admin_id, code, ttl_seconds=ttl_seconds)
    if ok:
        session['otp_expires_ts'] = int(expires_ts)
        session['otp_sent_ts'] = int(time.time())
        log_activity("Auth OTP Resent", f"user={session.get('otp_user', '-')}", "info")
    return redirect(url_for('login_otp'))


@app.route('/security/api-keys', methods=['GET'])
def security_list_api_keys():
    items = list_api_key_clients()
    return jsonify({"success": True, "items": items})


@app.route('/security/api-keys/create', methods=['POST'])
def security_create_api_key():
    req_json = request.get_json(silent=True) or {}
    name = str(req_json.get("name", "")).strip() or str(request.form.get("name", "")).strip() or "client"
    created = create_api_key_client(name)
    log_activity("API Key Created", f"id={created.get('id')} name={name}", "warning")
    return jsonify({"success": True, "item": created})


@app.route('/security/api-keys/revoke/<client_id>', methods=['POST'])
def security_revoke_api_key(client_id):
    ok = revoke_api_key_client(client_id)
    if ok:
        log_activity("API Key Revoked", f"id={client_id}", "warning")
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Client key not found"}), 404

@app.route('/logout')
def logout(): 
    session.clear()
    return redirect(url_for('login'))

def get_target_ip(node_id):
    node_key = str(node_id or "").strip()
    if not node_key:
        return None
    node_key_l = node_key.lower()

    nodes = get_all_servers()
    if node_key in nodes and nodes[node_key].get('ip'):
        return str(nodes[node_key]['ip']).strip()
    for nid, ninfo in nodes.items():
        if str(nid).strip().lower() == node_key_l and ninfo.get('ip'):
            return str(ninfo['ip']).strip()
    
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                normalized = line.replace('|', ' ').split()
                if not normalized:
                    continue
                nid = str(normalized[0]).strip().lower()
                if nid == node_key_l and len(normalized) >= 2:
                    return normalized[-1]
    return None

def run_ssh_sync(ip, cmd, timeout=20):
    if not ip:
        return False
    try:
        safe_cmd = cmd.replace('"', '\\"')
        full_ssh = f'ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{ip} "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; {safe_cmd}"'
        res = subprocess.run(full_ssh, shell=True, capture_output=True, text=True, timeout=timeout)
        return res.returncode == 0
    except Exception:
        return False


def _ensure_master_ssh_keypair():
    os.makedirs('/root/.ssh', mode=0o700, exist_ok=True)
    priv = '/root/.ssh/id_rsa'
    pub = f'{priv}.pub'
    if not os.path.exists(priv):
        res = subprocess.run(
            ['ssh-keygen', '-t', 'rsa', '-b', '4096', '-f', priv, '-N', ''],
            capture_output=True,
            text=True,
            timeout=30
        )
        if res.returncode != 0:
            err = (res.stderr or res.stdout or 'ssh-keygen failed').strip()
            return None, err[:300]
    if not os.path.exists(pub):
        res = subprocess.run(['ssh-keygen', '-y', '-f', priv], capture_output=True, text=True, timeout=20)
        if res.returncode != 0:
            err = (res.stderr or res.stdout or 'failed to derive public key').strip()
            return None, err[:300]
        with open(pub, 'w') as f:
            f.write(res.stdout.strip() + '\n')
    with open(pub, 'r', encoding='utf-8') as f:
        key = f.read().strip()
    if not key:
        return None, 'master public key is empty'
    return key, ''


def install_master_key_with_password(ip, ssh_user='root', ssh_password=''):
    """One-time password login that installs this panel's public key on a node.

    Password is not persisted. After this succeeds, existing key-based root SSH
    flows can install/manage Xray as before.
    """
    ip = str(ip or '').strip()
    ssh_user = str(ssh_user or 'root').strip() or 'root'
    ssh_password = str(ssh_password or '')
    if not ip or not ssh_password:
        return True, 'skipped'
    if ssh_user != 'root':
        return False, 'Only root SSH username is supported for automatic node setup right now.'
    if not shutil.which('sshpass'):
        return False, 'sshpass is not installed on the PanelMaster VPS. Run install_panel.sh/update dependencies first.'

    pubkey, err = _ensure_master_ssh_keypair()
    if not pubkey:
        return False, err or 'failed to read master public key'

    remote_cmd = (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        f"touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && "
        f"grep -qxF {shlex.quote(pubkey)} ~/.ssh/authorized_keys || "
        f"printf '%s\\n' {shlex.quote(pubkey)} >> ~/.ssh/authorized_keys"
    )
    env = os.environ.copy()
    env['SSHPASS'] = ssh_password
    res = subprocess.run(
        [
            'sshpass', '-e', 'ssh',
            '-o', 'ConnectTimeout=20',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'PreferredAuthentications=password',
            '-o', 'PubkeyAuthentication=no',
            f'{ssh_user}@{ip}',
            remote_cmd
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=45
    )
    if res.returncode != 0:
        err = (res.stderr or res.stdout or 'password SSH key install failed').strip()
        return False, err[:500]

    verify = subprocess.run(
        ['ssh', '-o', 'ConnectTimeout=12', '-o', 'StrictHostKeyChecking=no', f'root@{ip}', 'echo ok'],
        capture_output=True,
        text=True,
        timeout=20
    )
    if verify.returncode != 0:
        err = (verify.stderr or verify.stdout or 'key verification failed').strip()
        return False, err[:500]
    return True, 'ok'

def measure_ping_latency_ms(ip):
    if not ip:
        return None
    ip = str(ip).strip()
    try:
        res = subprocess.run(
            f"ping -c 1 -W 2 {ip}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=4
        )
        if res.returncode != 0:
            return None
        out = (res.stdout or "") + "\n" + (res.stderr or "")
        m = re.search(r"time[=<]\s*([0-9.]+)\s*ms", out)
        if not m:
            return None
        return round(float(m.group(1)), 2)
    except Exception:
        return None

def _append_activity_log(entry):
    if not ACTIVITY_LOG_LOCK.acquire(blocking=False):
        return
    try:
        history = []
        if os.path.exists(ACTIVITY_LOG_FILE):
            try:
                with open(ACTIVITY_LOG_FILE, 'r') as f:
                    history = json.load(f)
            except Exception:
                history = []
        history.insert(0, entry)
        history = history[:500]
        with open(ACTIVITY_LOG_FILE, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass
    finally:
        ACTIVITY_LOG_LOCK.release()

def log_activity(action, details="", level="info"):
    try:
        entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": str(action or "").strip(),
            "details": str(details or "").strip(),
            "level": str(level or "info").strip().lower()
        }
        # Keep business routes fast: never block request flow for logging.
        threading.Thread(target=_append_activity_log, args=(entry,), daemon=True).start()
    except Exception:
        pass

@app.route('/api/user_ip/<username>')
def api_user_ip(username):
    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
    
    if username not in db: return jsonify({"status": "error", "msg": "User not found"})
    
    uinfo = db[username]
    node_id = uinfo.get('node')
    port = uinfo.get('port', '443')
    proto = uinfo.get('protocol', 'v2')
    
    node_ip = get_target_ip(node_id)
    if not node_ip: return jsonify({"status": "error", "msg": "Node offline"})
    
    ips_info = get_active_ips(node_ip, port, proto, username)
    return jsonify({"status": "success", "data": ips_info})

@app.route('/fix_node_logs/<node_id>', methods=['POST'])
def fix_node_logs(node_id):
    ip = get_target_ip(node_id)
    if ip:
        cmds = [
            "mkdir -p /var/log/xray",
            "touch /var/log/xray/access.log",
            "chmod 777 /var/log/xray/access.log",
            "grep -q 'access.log' /usr/local/etc/xray/config.json || sed -i 's/\"log\": {/\"log\": {\\n    \"access\": \"\\/var\\/log\\/xray\\/access.log\",/g' /usr/local/etc/xray/config.json",
            "systemctl restart xray"
        ]
        execute_ssh_bg(ip, cmds)
    return redirect(request.referrer)

@app.route('/set_node_health/<node_id>', methods=['POST'])
def set_node_health(node_id):
    health = request.form.get('health', 'green')
    with db_lock:
        ndb = {}
        if os.path.exists(NODES_DB):
            try:
                with open(NODES_DB, 'r') as f: ndb = json.load(f)
            except: pass
        if node_id not in ndb: ndb[node_id] = {"used_bytes": 0, "limit_tb": 0, "health": "green"}
        ndb[node_id]["health"] = health
        with open(NODES_DB, 'w') as f: json.dump(ndb, f)
    return redirect(request.referrer)

@app.route('/set_node_traffic/<node_id>', methods=['POST'])
def set_node_traffic(node_id):
    try: tb = float(request.form.get('limit_tb', 0))
    except: tb = 0.0
    with db_lock:
        ndb = {}
        if os.path.exists(NODES_DB):
            try:
                with open(NODES_DB, 'r') as f: ndb = json.load(f)
            except: pass
        if node_id not in ndb: ndb[node_id] = {"used_bytes": 0, "limit_tb": 0, "health": "green"}
        ndb[node_id]["limit_tb"] = tb
        with open(NODES_DB, 'w') as f: json.dump(ndb, f)
    return redirect(request.referrer)

@app.route('/reset_node_traffic/<node_id>', methods=['POST'])
def reset_node_traffic(node_id):
    with db_lock:
        ndb = {}
        if os.path.exists(NODES_DB):
            try:
                with open(NODES_DB, 'r') as f: ndb = json.load(f)
            except: pass
        if node_id in ndb:
            ndb[node_id]["used_bytes"] = 0
            with open(NODES_DB, 'w') as f: json.dump(ndb, f)
    return redirect(request.referrer)

def build_keys_and_sync_cmds(db):
    cmds_by_ip = {}
    for uname, uinfo in db.items():
        if not isinstance(uinfo, dict):
            continue
        node_id = uinfo.get('node')
        node_ip = get_target_ip(node_id)
        if not node_ip:
            continue
        node_ip = str(node_ip).strip()
        uid = uinfo.get('uuid')
        port = uinfo.get('port')
        proto = uinfo.get('protocol', 'v2')
        safe_u = urllib.parse.quote(uname)

        if proto == 'v2':
            expected_key = f"vless://{uid}@{node_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
            cmd = f"/usr/local/bin/v2ray-node-add-vless {shlex.quote(str(uname))} {shlex.quote(str(uid))}"
        else:
            credentials = f"chacha20-ietf-poly1305:{uid}"
            b64_creds = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8').rstrip('=')
            expected_key = f"ss://{b64_creds}@{node_ip}:{port}#{safe_u}"
            cmd = get_safe_add_out_cmd(uname, uid, port)

        uinfo['key'] = expected_key
        if not uinfo.get('is_blocked', False):
            cmds_by_ip.setdefault(node_ip, []).append(cmd)
    return cmds_by_ip

@app.route('/')
def dashboard():
    nodes = get_nodes()
    auto_groups = load_auto_groups()
    db = {}
    ndb = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: pass
        if os.path.exists(NODES_DB):
            try:
                with open(NODES_DB, 'r') as f: ndb = json.load(f)
            except: pass
                
    config = load_config()
    activity_logs = []
    if os.path.exists(ACTIVITY_LOG_FILE):
        try:
            with open(ACTIVITY_LOG_FILE, 'r') as f:
                activity_logs = json.load(f)
        except Exception:
            activity_logs = []
    active_users = check_live_status(db)
    node_stats = []
    group_stats = []
    
    node_used_bytes = {}
    group_used_bytes = {}
    
    for uname, uinfo in db.items():
        if not isinstance(uinfo, dict): continue
        nid = uinfo.get('node')
        gid = uinfo.get('group')
        try: u_bytes = float(uinfo.get('used_bytes', 0))
        except: u_bytes = 0.0
        if nid: node_used_bytes[nid] = node_used_bytes.get(nid, 0) + u_bytes
        if gid: group_used_bytes[gid] = group_used_bytes.get(gid, 0) + u_bytes
    
    all_servers = get_all_servers()
    sick_nodes = {'blue': [], 'yellow': [], 'orange': [], 'red': []}
    sick_count = 0
    for nid, info in all_servers.items():
        h = ndb.get(nid, {}).get("health", "green")
        if h in sick_nodes:
            sick_nodes[h].append({"id": nid, "name": info.get('name', nid), "ip": info.get('ip', '')})
            sick_count += 1
            
    for nid, info in nodes.items():
        total_count = sum(1 for i in db.values() if isinstance(i, dict) and i.get('node') == nid and not i.get('group'))
        live_count = sum(1 for uname, i in db.items() if isinstance(i, dict) and i.get('node') == nid and not i.get('group') and uname in active_users and not i.get('is_blocked'))
        
        ninfo = ndb.get(nid, {})
        limit_tb = float(ninfo.get("limit_tb", 0))
        used_gb = float(node_used_bytes.get(nid, 0)) / (1024**3)
        limit_gb = limit_tb * 1024
        is_alarm = limit_gb > 0 and used_gb >= limit_gb
        health = ninfo.get("health", "green")

        node_stats.append({
            "id": nid, "name": info.get('name', nid), "ip": info.get('ip', ''), 
            "total": total_count, "live": live_count, "disabled": nid in config.get('disabled_nodes', []),
            "used_gb": used_gb, "limit_tb": limit_tb, "is_alarm": is_alarm, "health": health
        })
        
    for gid, gdata in auto_groups.items():
        limit = gdata.get("limit", 30)
        g_nodes = gdata.get("nodes", {})
        g_keys = sum(1 for i in db.values() if isinstance(i, dict) and i.get("group") == gid)
        g_active = sum(1 for i in db.values() if isinstance(i, dict) and i.get("group") == gid and not i.get('is_blocked') and i.get('is_online'))
        g_used_gb = group_used_bytes.get(gid, 0) / (1024**3)
        api_domain = gdata.get("api_domain", "")
        group_stats.append({"id": gid, "name": gdata.get("name", gid), "limit": limit, "api_domain": api_domain, "node_count": len(g_nodes), "total_keys": g_keys, "active_keys": g_active, "used_gb": g_used_gb})

    backup_inventory = list_backups(BACKUP_DIR)
    raw_backups = backup_inventory.get("node_backups", {})
    full_backups = backup_inventory.get("full_backups", [])
    custom_backups = {}
    auto_backups = {}
    orphaned_backups = {}
    
    auto_nids_map = {}
    for gid, gdata in auto_groups.items():
        auto_backups[gid] = {"name": gdata.get('name', gid), "nodes": {}}
        for nid, ninfo in gdata.get('nodes', {}).items():
            ip = str(ninfo.get('ip')).strip() if isinstance(ninfo, dict) else str(ninfo).strip()
            auto_nids_map[nid] = {
                "gid": gid,
                "name": all_servers.get(nid, {}).get('name', nid),
                "ip": ip
            }
            
    for nid, files in raw_backups.items():
        # Prefer showing nodes under their group section when available.
        if nid in auto_nids_map:
            nmeta = auto_nids_map[nid]
            gid = nmeta["gid"]
            auto_backups[gid]["nodes"][nid] = {
                "name": nmeta["name"],
                "ip": nmeta["ip"],
                "files": files
            }
        elif nid in nodes:
            custom_backups[nid] = {"name": nodes[nid].get('name', nid), "ip": nodes[nid].get('ip', ''), "files": files}
        else:
            orphaned_backups[nid] = files
            
    auto_backups = {k: v for k, v in auto_backups.items() if v["nodes"]}

    return render_template(
        'dashboard.html',
        nodes=node_stats,
        groups=group_stats,
        config=config,
        custom_backups=custom_backups,
        auto_backups=auto_backups,
        orphaned_backups=orphaned_backups,
        full_backups=full_backups,
        sick_nodes=sick_nodes,
        sick_count=sick_count,
        activity_logs=activity_logs[:200]
    )

@app.route('/add_auto_group', methods=['POST'])
def add_auto_group():
    gid = request.form.get('group_id', '').strip().replace(" ", "_")
    gname = request.form.get('group_name', '').strip()
    limit = int(request.form.get('limit', 30))
    api_domain = request.form.get('api_domain', '').strip()
    
    if gid and gname:
        groups = load_auto_groups()
        groups[gid] = {"name": gname, "limit": limit, "api_domain": api_domain, "nodes": {}}
        save_auto_groups(groups)
        log_activity("Add Auto Group", f"group={gid} name={gname} limit={limit}", "success")
    return redirect(url_for('dashboard'))

@app.route('/delete_auto_group/<group_id>', methods=['POST'])
def delete_auto_group(group_id):
    groups = load_auto_groups()
    if group_id in groups:
        del groups[group_id]
        save_auto_groups(groups)
        log_activity("Delete Auto Group", f"group={group_id}", "warning")
    return redirect(url_for('dashboard'))


def _node_id_equals(a, b):
    return str(a or "").strip().lower() == str(b or "").strip().lower()


def _node_id_exists_ci(candidate_id, all_nodes):
    c = str(candidate_id or "").strip()
    return any(_node_id_equals(nid, c) for nid in (all_nodes or {}).keys())


def _is_node_runtime_ready(node_ip):
    ip = str(node_ip or "").strip()
    if not ip:
        return False
    try:
        cmd = (
            "command -v /usr/local/bin/xray >/dev/null 2>&1 && "
            "command -v /usr/local/bin/v2ray-node-add-out >/dev/null 2>&1 && "
            "command -v /usr/local/bin/v2ray-node-add-vless >/dev/null 2>&1 && "
            "(systemctl is-active --quiet xray || pgrep -x xray >/dev/null 2>&1)"
        )
        res = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=no", f"root@{ip}", cmd],
            capture_output=True,
            text=True,
            timeout=12
        )
        return res.returncode == 0
    except Exception:
        return False


def _hard_remove_node_references(
    node_id,
    remove_from_nodes_list=True,
    remove_backups=False,
    remove_group_links=True
):
    """
    Remove every known reference of a node id (case-insensitive) from:
    - auto groups
    - nodes_list.txt
    - nodes_db.json
    - users_db.json (users pinned to node)
    - config disabled/monitor-skip arrays
    """
    node_norm = str(node_id or "").strip().lower()
    removed = {"groups": 0, "users": 0, "nodes_db": 0, "config": 0}

    # 1) Auto groups: remove matching node keys, regardless of exact case.
    if remove_group_links:
        groups = load_auto_groups()
        groups_changed = False
        for gid, gdata in groups.items():
            gnodes = (gdata or {}).get("nodes", {})
            if not isinstance(gnodes, dict):
                continue
            to_del = [nid for nid in gnodes.keys() if _node_id_equals(nid, node_norm)]
            for nid in to_del:
                del gnodes[nid]
                removed["groups"] += 1
                groups_changed = True
        if groups_changed:
            save_auto_groups(groups)

    # 2) nodes_list.txt: drop line by normalized node id.
    if remove_from_nodes_list and os.path.exists(NODES_LIST):
        try:
            with open(NODES_LIST, 'r') as f:
                lines = f.readlines()
            with open(NODES_LIST, 'w') as f:
                for line in lines:
                    raw = str(line or "").strip()
                    if not raw:
                        continue
                    if '|' in raw:
                        parts = raw.split('|')
                        line_id = str(parts[0]).strip() if parts else ""
                    else:
                        parts = raw.rsplit(' ', 1)
                        line_id = str(parts[0]).strip() if len(parts) == 2 else ""
                    if _node_id_equals(line_id, node_norm):
                        continue
                    f.write(line)
        except Exception:
            pass

    # 3) nodes_db.json: remove stale node stats row.
    with db_lock:
        if os.path.exists(NODES_DB):
            try:
                with open(NODES_DB, 'r') as f:
                    ndb = json.load(f)
            except Exception:
                ndb = {}
            if isinstance(ndb, dict):
                to_del = [nid for nid in ndb.keys() if _node_id_equals(nid, node_norm)]
                for nid in to_del:
                    del ndb[nid]
                    removed["nodes_db"] += 1
                if to_del:
                    with open(NODES_DB, 'w') as f:
                        json.dump(ndb, f, indent=4)

        # 4) users_db.json: remove users bound to deleted node (case-insensitive).
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f:
                    db = json.load(f)
            except Exception:
                db = {}
            if isinstance(db, dict):
                to_del = [
                    uname for uname, info in db.items()
                    if isinstance(info, dict) and _node_id_equals(info.get('node', ''), node_norm)
                ]
                for uname in to_del:
                    del db[uname]
                    removed["users"] += 1
                if to_del:
                    with open(USERS_DB, 'w') as f:
                        json.dump(db, f, indent=4)

    # 5) config.json lists: disabled_nodes + monitor_skip_nodes.
    try:
        cfg = load_config()
        changed = False
        for key in ("disabled_nodes", "monitor_skip_nodes"):
            arr = cfg.get(key, [])
            if not isinstance(arr, list):
                continue
            new_arr = [x for x in arr if not _node_id_equals(x, node_norm)]
            if len(new_arr) != len(arr):
                removed["config"] += (len(arr) - len(new_arr))
                cfg[key] = new_arr
                changed = True
        if changed:
            save_config(cfg)
    except Exception:
        pass

    if remove_backups and os.path.exists(BACKUP_DIR):
        for root, _, files in os.walk(BACKUP_DIR):
            for f in files:
                if (
                    f.startswith(f"backup_{node_id}_")
                    or f.startswith(f"node_backup__{node_id}__")
                    or f"__{node_id}__" in f
                ):
                    try:
                        os.remove(os.path.join(root, f))
                    except Exception:
                        pass
    return removed

@app.route('/group/<group_id>')
def group_view(group_id):
    groups = load_auto_groups()
    if group_id not in groups: 
        return redirect(url_for('dashboard'))
        
    group = groups[group_id]
    db = {}
    ndb = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
        if os.path.exists(NODES_DB):
            try:
                with open(NODES_DB, 'r') as f: ndb = json.load(f)
            except: pass
            
    active_users = check_live_status(db)
    users = []
    server_stats = []
    g_nodes = group.get("nodes", {})
    counts = {nid: 0 for nid in g_nodes.keys()}
    
    node_used_bytes = {}
    group_total_bytes = 0
    current_date_str = datetime.now().strftime("%Y-%m-%d")
    
    db_changed = False
    changed_users_by_node = {}
    cmds_by_ip = {}
    
    for uname, info in db.items():
        if not isinstance(info, dict): continue
        if info.get('group') == group_id:
            nid = info.get('node')
            node_ip = get_target_ip(nid)
            
            if node_ip:
                uid = info.get('uuid')
                port = info.get('port')
                proto = info.get('protocol', 'v2')
                display = get_display_name(uname, info)
                safe_u = urllib.parse.quote(display)

                if proto == 'v2':
                    expected_key = f"vless://{uid}@{node_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
                    cmd = f"/usr/local/bin/v2ray-node-add-vless {shlex.quote(str(display))} {shlex.quote(str(uid))}"
                else:
                    credentials = f"chacha20-ietf-poly1305:{uid}"
                    b64_creds = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8').rstrip('=')
                    expected_key = f"ss://{b64_creds}@{node_ip}:{port}#{safe_u}"
                    cmd = get_safe_add_out_cmd(display, uid, port)
                    
                if info.get('key') != expected_key:
                    info['key'] = expected_key
                    db_changed = True
                    changed_users_by_node.setdefault(nid, set()).add(uname)
                    if not info.get('is_blocked', False):
                        cmds_by_ip.setdefault(node_ip, []).append(cmd)
            
            info['used_bytes'] = float(info.get('used_bytes', 0))
            info['total_gb'] = float(info.get('total_gb', 0))
            info['used_gb_str'] = f"{(info['used_bytes'] / (1024**3)):.2f}"
            info['db_key'] = uname
            info['username'] = get_display_name(uname, info)
            info['actual_key'] = info.get('key') or "No Key Found"
            user_node_ip = str(get_target_ip(nid) or "").strip()
            online_ips = info.get('online_on_ips', [])
            info['is_active'] = bool(user_node_ip and isinstance(online_ips, list) and user_node_ip in online_ips and not info.get('is_blocked'))
            info['active_on_node'] = nid if info['is_active'] else ""
            info['protocol_label'] = "VLESS" if info.get('protocol') == 'v2' else "Outline SS"
            
            exp_str = info.get('expire_date')
            is_expired = True if (exp_str and current_date_str > exp_str) else False
            
            if is_expired: info['status_label'] = "Expired"
            elif info.get('is_blocked'): info['status_label'] = "Blocked"
            elif info['is_active']: info['status_label'] = "Online"
            else: info['status_label'] = "Offline"
                
            users.append(info)
            if nid in counts: counts[nid] += 1
            if nid: node_used_bytes[nid] = node_used_bytes.get(nid, 0) + info['used_bytes']
            group_total_bytes += info['used_bytes']
            
    if db_changed:
        with db_lock:
            with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)
        for changed_nid, changed_users in changed_users_by_node.items():
            changed_ip = get_target_ip(changed_nid)
            if changed_ip and changed_users:
                threading.Thread(
                    target=sync_new_node_to_subpanel,
                    args=(group_id, changed_nid, str(changed_ip).strip()),
                    daemon=True
                ).start()
    for ip, cmds in cmds_by_ip.items():
        prefix = "systemctl() { true; }; export -f systemctl; "
        suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
        execute_ssh_bg(ip, [prefix + " ; ".join(cmds) + suffix])
            
    users = sorted(users, key=lambda x: int(x.get('key_id', 0)))
    group_used_gb = group_total_bytes / (1024**3)
            
    for nid, ndata in g_nodes.items():
        if isinstance(ndata, dict):
            nip = str(ndata.get("ip")).strip()
            limit = int(ndata.get("limit", group.get("limit", 30)))
            nname = str(ndata.get("name", "")).strip() or nid
        else:
            nip = str(ndata).strip()
            limit = int(group.get("limit", 30))
            nname = nid
            
        ninfo = ndb.get(nid, {})
        limit_tb = float(ninfo.get("limit_tb", 0))
        used_gb = node_used_bytes.get(nid, 0) / (1024**3)
        limit_gb = limit_tb * 1024
        is_alarm = limit_tb > 0 and used_gb >= limit_gb
        health = ninfo.get("health", "green")
        
        node_ip_for_active = str(get_target_ip(nid) or "").strip()
        active_count = sum(
            1 for ui in db.values()
            if isinstance(ui, dict) and ui.get('group') == group_id
            and not ui.get('is_blocked') and node_ip_for_active
            and isinstance(ui.get('online_on_ips', []), list) and node_ip_for_active in ui.get('online_on_ips', [])
        )

        server_stats.append({
            "id": nid,
            "name": nname,
            "ip": nip,
            "count": counts[nid],
            "active": active_count,
            "limit": limit,
            "used_gb": used_gb,
            "limit_tb": limit_tb,
            "is_alarm": is_alarm,
            "health": health
        })
        
    return render_template('group.html', group_id=group_id, group=group, users=users, server_stats=server_stats, group_used_gb=group_used_gb)

def sync_new_node_to_subpanel(group_id, new_node_id, new_node_ip):
    time.sleep(2)
    try:
        groups = load_auto_groups()
        gmeta = groups.get(group_id, {}) or {}
        group_name = str(gmeta.get("name", "")).strip() if isinstance(gmeta, dict) else ""
        if not group_name:
            group_name = str(group_id)
        nmeta = (groups.get(group_id, {}) or {}).get("nodes", {}).get(new_node_id, {})
        display_name = str(nmeta.get("name", "")).strip() if isinstance(nmeta, dict) else ""
        if not display_name:
            display_name = str(new_node_id)

        with db_lock:
            if not os.path.exists(USERS_DB): return
            with open(USERS_DB, 'r') as f: db = json.load(f)

        user_keys = {}
        for uname, uinfo in db.items():
            if isinstance(uinfo, dict) and uinfo.get('group') == group_id and uinfo.get('token'):
                uid = uinfo.get('uuid')
                port = uinfo.get('port')
                proto = uinfo.get('protocol', 'v2')
                display = get_display_name(uname, uinfo)
                safe_u = urllib.parse.quote(display)

                if proto == 'v2':
                    k = f"vless://{uid}@{new_node_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
                else:
                    k = {
                        "server": str(new_node_ip),
                        "server_port": int(port),
                        "password": str(uid),
                        "method": "chacha20-ietf-poly1305",
                        "prefix": "\u0016\u0003\u0001\u0005\u00f2\u0001\u0000\u0005\u00ee\u0003\u0003"
                    }

                user_keys[display] = k

        if not user_keys: return 

        event_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        node_suffix = str(new_node_id or "").strip().lower()
        version = f"{event_at}#{node_suffix}"
        _set_sync_new_server_status(
            last_attempt_at=event_at,
            last_group_id=str(group_id),
            last_node_id=str(new_node_id),
            last_version=str(version),
            last_status="sending",
            last_url="",
            last_http_code=0,
            last_error="",
            last_body_preview=""
        )

        payload = {
            "masterGroupId": group_id,
            "groupName": group_name,
            "version": version,
            "at": event_at,
            "newServerId": new_node_id,
            "newServerDisplayName": display_name,
            "userKeys": user_keys
        }
        
        from core_monitor import _build_sync_url, _get_sync_api_key
        sync_key = _get_sync_api_key()
        primary_url = _build_sync_url("sync-new-server")
        if not primary_url or not sync_key:
            print(f"[sync-new-server] SKIP — no sync URL or API key configured")
            return
        headers = {"Content-Type": "application/json", "x-api-key": sync_key}
        urls = [primary_url]
        delivered = False
        for url in urls:
            try:
                r = requests.post(url, json=payload, headers=headers, timeout=10)
                body_preview = str((r.text or "").strip()).replace("\n", " ")[:220]
                _set_sync_new_server_status(
                    last_url=str(url),
                    last_http_code=int(r.status_code),
                    last_body_preview=body_preview,
                    last_error=""
                )
                if 200 <= r.status_code < 300:
                    delivered = True
                    _set_sync_new_server_status(
                        last_ok_at=event_at,
                        last_status="ok"
                    )
                    break
            except Exception:
                _set_sync_new_server_status(
                    last_url=str(url),
                    last_status="request_error",
                    last_error="request_failed"
                )
        if not delivered:
            _set_sync_new_server_status(last_status="failed_all_targets")
            print(f"Sync New Server Error: delivery failed for {group_id}/{new_node_id}")
        
    except Exception as e:
        _set_sync_new_server_status(last_status="exception", last_error=str(e)[:220])
        print(f"Sync New Server Error: {e}")

def provision_group_users_to_node(group_id, node_id, node_ip, only_usernames=None):
    """
    Ensure existing group users are actually created on the target node.
    This is required for newly added/recovered nodes before external sync.
    """
    try:
        with db_lock:
            if not os.path.exists(USERS_DB):
                return 0
            with open(USERS_DB, 'r') as f:
                db = json.load(f)

        only_set = set(only_usernames or [])
        cmds = []
        added_count = 0

        for uname, uinfo in db.items():
            if not isinstance(uinfo, dict):
                continue
            if uinfo.get('group') != group_id:
                continue
            if only_set and uname not in only_set:
                continue
            if bool(uinfo.get('is_blocked', False)):
                continue

            uid = str(uinfo.get('uuid', '')).strip()
            proto = str(uinfo.get('protocol', 'out')).strip()
            if not uid:
                continue

            if proto == 'v2':
                cmd = f"/usr/local/bin/v2ray-node-add-vless {shlex.quote(str(uname))} {shlex.quote(str(uid))}"
            else:
                port = str(uinfo.get('port', '')).strip()
                if not port:
                    continue
                cmd = get_safe_add_out_cmd(uname, uid, port)
            cmds.append(cmd)
            added_count += 1

        if not cmds:
            return 0

        # Restart xray once per chunk to avoid excessive restarts with large groups.
        chunk_size = 80
        for i in range(0, len(cmds), chunk_size):
            chunk = cmds[i:i + chunk_size]
            prefix = "systemctl() { true; }; export -f systemctl; "
            suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
            execute_ssh_bg(node_ip, [prefix + " ; ".join(chunk) + suffix])
        return added_count
    except Exception as e:
        print(f"Provision Users Error ({group_id}/{node_id}): {e}")
        return 0

def deploy_and_sync_group_node(group_id, node_id, node_ip, only_usernames=None):
    """
    1) Provision existing users on server node.
    2) Push updated key mapping to external panel.
    """
    if not _is_node_runtime_ready(node_ip):
        log_activity("Deploy Node Blocked", f"group={group_id} node={node_id} reason=node_not_ready", "error")
        return
    provision_group_users_to_node(group_id, node_id, node_ip, only_usernames=only_usernames)
    time.sleep(1)
    sync_new_node_to_subpanel(group_id, node_id, node_ip)


def _bootstrap_group_node_after_add(group_id, node_id, node_ip):
    """
    Auto-bootstrap a newly added group node so it works without manual reinstall.
    """
    ip = str(node_ip or "").strip()
    if not ip:
        log_activity("Group Node Bootstrap Failed", f"group={group_id} node={node_id} reason=missing_ip", "error")
        return
    try:
        if not _is_node_runtime_ready(ip):
            log_activity("Group Node Bootstrap", f"group={group_id} node={node_id} step=auto_install", "info")
            ok, err = _run_node_install_script(node_id, ip)
            if not ok:
                log_activity(
                    "Group Node Bootstrap Failed",
                    f"group={group_id} node={node_id} reason=install_failed err={str(err)[:120]}",
                    "error"
                )
                return
        deploy_and_sync_group_node(group_id, node_id, ip)
        log_activity("Group Node Bootstrap Success", f"group={group_id} node={node_id}", "success")
    except Exception as e:
        log_activity("Group Node Bootstrap Error", f"group={group_id} node={node_id} error={str(e)[:120]}", "error")

@app.route('/add_server_to_group/<group_id>', methods=['POST'])
def add_server_to_group(group_id):
    nid = request.form.get('node_id', '').strip().replace(" ", "_")
    nname = request.form.get('node_name', '').strip()
    nip = request.form.get('node_ip', '').strip()
    ssh_user = request.form.get('ssh_username', 'root').strip() or 'root'
    ssh_password = request.form.get('ssh_password', '')
    limit = int(request.form.get('limit', 30))
    groups = load_auto_groups()
    nodes = get_all_servers()
    
    if _node_id_exists_ci(nid, nodes):
        return f"<script>alert('Error: Server ID [{nid}] already exists!'); window.history.back();</script>"
        
    if group_id in groups and nid and nip:
        ok, msg = install_master_key_with_password(nip, ssh_user, ssh_password)
        if not ok:
            alert_msg = json.dumps(f"SSH key setup failed: {msg}")
            log_activity("Add Server SSH Key Failed", f"group={group_id} node={nid} ip={nip} error={str(msg)[:140]}", "error")
            return f"<script>alert({alert_msg}); window.history.back();</script>"
        groups[group_id]["nodes"][nid] = {
            "ip": nip,
            "limit": limit,
            "name": nname or nid
        }
        save_auto_groups(groups)
        threading.Thread(target=_bootstrap_group_node_after_add, args=(group_id, nid, nip), daemon=True).start()
        log_activity("Add Server To Group", f"group={group_id} node={nid} name={nname or nid} ip={nip} ssh_key_setup={msg}", "success")
        
    return redirect(f'/group/{group_id}?newly_added={nid}')

@app.route('/resync_server_to_subpanel/<group_id>/<node_id>', methods=['POST'])
def resync_server_to_subpanel(group_id, node_id):
    groups = load_auto_groups()
    if group_id not in groups or node_id not in groups[group_id].get("nodes", {}):
        return redirect(request.referrer or url_for('dashboard'))

    ndata = groups[group_id]["nodes"][node_id]
    node_ip = str(ndata.get("ip")).strip() if isinstance(ndata, dict) else str(ndata).strip()
    if not node_ip:
        node_ip = get_target_ip(node_id) or ""
    node_ip = str(node_ip).strip()
    if not node_ip:
        return redirect(request.referrer or f'/group/{group_id}')

    # Manual recovery push + node provisioning for missed/failed sync cases.
    threading.Thread(
        target=deploy_and_sync_group_node,
        args=(group_id, node_id, node_ip),
        daemon=True
    ).start()
    log_activity("Manual Resync", f"group={group_id} node={node_id}", "info")
    return redirect(request.referrer or f'/group/{group_id}')

@app.route('/resync_group_to_subpanel/<group_id>', methods=['POST'])
def resync_group_to_subpanel(group_id):
    groups = load_auto_groups()
    gdata = groups.get(group_id, {})
    gnodes = gdata.get("nodes", {}) if isinstance(gdata, dict) else {}
    if not gnodes:
        return redirect(request.referrer or url_for('dashboard'))

    queued = 0
    for node_id, ndata in gnodes.items():
        node_ip = str(ndata.get("ip")).strip() if isinstance(ndata, dict) else str(ndata).strip()
        if not node_ip:
            node_ip = get_target_ip(node_id) or ""
        node_ip = str(node_ip).strip()
        if not node_ip:
            continue
        # Safety: group-level sync should only push webhook updates to external panel.
        # Do NOT reprovision users here, otherwise all nodes restart xray at once.
        threading.Thread(
            target=sync_new_node_to_subpanel,
            args=(group_id, node_id, node_ip),
            daemon=True
        ).start()
        queued += 1

    log_activity("Manual Group Resync", f"group={group_id} nodes_queued={queued} mode=webhook_only", "info")
    return redirect(request.referrer or f'/group/{group_id}')

@app.route('/delete_server_from_group/<group_id>/<node_id>', methods=['POST'])
def delete_server_from_group(group_id, node_id):
    groups = load_auto_groups()
    gnodes = (groups.get(group_id, {}) or {}).get("nodes", {})
    match_ids = [nid for nid in gnodes.keys() if _node_id_equals(nid, node_id)]
    node_ip = ""
    for mid in match_ids:
        ndata = gnodes.get(mid, {})
        maybe_ip = str(ndata.get("ip")).strip() if isinstance(ndata, dict) else str(ndata).strip()
        if maybe_ip and not node_ip:
            node_ip = maybe_ip
        del gnodes[mid]
    if match_ids:
        save_auto_groups(groups)

    users_to_delete = []
    users_removed = 0
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f:
                    db = json.load(f)
            except Exception:
                db = {}
            users_to_delete = [
                u for u, info in db.items()
                if isinstance(info, dict)
                and _node_id_equals(info.get('node', ''), node_id)
                and _node_id_equals(info.get('group', ''), group_id)
            ]
            # Delete DB rows directly. Do not call bulk_delete_keys() here:
            # for SS users it may fan cleanup commands out to remaining group
            # nodes, and same-port users on those nodes can be removed by
            # mistake. Removing a server from a group should only orphan-clean
            # PanelMaster state for that deleted node.
            for uname in users_to_delete:
                if uname in db:
                    del db[uname]
                    users_removed += 1
            if users_removed:
                with open(USERS_DB, 'w') as f:
                    json.dump(db, f, indent=4)

    # Also clear stale node references from status/config tables.
    removed = _hard_remove_node_references(
        node_id,
        remove_from_nodes_list=False,
        remove_backups=False,
        remove_group_links=False
    )
    users_removed += int(removed.get('users', 0) or 0)
    log_activity(
        "Delete Server From Group",
        f"group={group_id} node={node_id} users_removed={users_removed} group_refs_removed={removed.get('groups', 0)}",
        "warning"
    )
            
    return redirect(f'/group/{group_id}')

@app.route('/edit_group_limit/<group_id>', methods=['POST'])
def edit_group_limit(group_id):
    new_limit = int(request.form.get('limit', 30))
    success, msg = rebalance_auto_node(group_id, new_limit)
    if not success: 
        return f"<script>alert('{msg}'); window.location.href='/group/{group_id}';</script>"
    log_activity("Edit Group Limit", f"group={group_id} limit={new_limit}", "info")
    return redirect(f'/group/{group_id}')

@app.route('/edit_server_limit/<group_id>/<node_id>', methods=['POST'])
def edit_server_limit(group_id, node_id):
    new_limit = int(request.form.get('limit', 30))
    success, msg = rebalance_auto_node(group_id, new_limit, specific_node=node_id)
    if not success: 
        return f"<script>alert('{msg}'); window.location.href='/group/{group_id}';</script>"
    log_activity("Edit Server Limit", f"group={group_id} node={node_id} limit={new_limit}", "info")
    return redirect(f'/group/{group_id}')


@app.route('/edit_server_name/<group_id>/<node_id>', methods=['POST'])
def edit_server_name(group_id, node_id):
    new_name = str(request.form.get('node_name', '')).strip()
    if not new_name:
        return redirect(f'/group/{group_id}')
    groups = load_auto_groups()
    if group_id not in groups or node_id not in groups[group_id].get("nodes", {}):
        return redirect(f'/group/{group_id}')

    ndata = groups[group_id]["nodes"][node_id]
    if isinstance(ndata, dict):
        ndata["name"] = new_name
    else:
        ndata = {"ip": str(ndata).strip(), "limit": int(groups[group_id].get("limit", 30)), "name": new_name}
    groups[group_id]["nodes"][node_id] = ndata
    save_auto_groups(groups)
    log_activity("Edit Server Name", f"group={group_id} node={node_id} name={new_name}", "info")
    return redirect(f'/group/{group_id}')

@app.route('/add_user_auto', methods=['POST'])
def add_user_auto():
    gid = request.form.get('group_id', '').strip()
    mode = request.form.get('creation_mode', 'single')
    
    raw_usernames = []
    if mode == 'single': 
        raw_usernames = [request.form.get('single_username', '')]
    elif mode == 'list': 
        raw_usernames = re.split(r'[,\n\r]+', request.form.get('list_usernames', ''))
    elif mode == 'pattern':
        base = request.form.get('base_name', '').strip()
        try: start = int(request.form.get('start_num') or 1)
        except: start = 1
        try: qty = int(request.form.get('qty') or 1)
        except: qty = 1
        raw_usernames = [f"{base}{start+i}" for i in range(qty)]

    try: gb = float(request.form.get('total_gb') or 0)
    except: gb = 0.0
    try: days = int(request.form.get('expire_days') or 30)
    except: days = 30
    
    proto = request.form.get('protocol', 'v2')

    success, msg = add_keys(None, gid, raw_usernames, gb, days, proto, is_auto=True)
    if not success: 
        return f"<script>alert('{msg}'); window.history.back();</script>"
    log_activity("Add Auto Users", f"group={gid} mode={mode} protocol={proto}", "success")
    return redirect(f'/group/{gid}')

# 🚀 ဒီလမ်းကြောင်းလေးက ပြဿနာရဲ့ အဓိက တရားခံပဲ! 🚀
@app.route('/node/<node_id>')
def node_view(node_id):
    nodes = get_all_servers()
    if node_id not in nodes: 
        return redirect(url_for('dashboard'))
        
    node_info = nodes[node_id]
    node_ip = str(node_info.get('ip', '')).strip()
    
    db = {}
    ndb = {}
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: pass
        if os.path.exists(NODES_DB):
            try:
                with open(NODES_DB, 'r') as f: ndb = json.load(f)
            except: pass
            
    config = load_config()
    active_users = check_live_status(db)
    node_active_users = check_live_status_for_node(db, node_ip)
    auto_groups = load_auto_groups()
    users = []
    node_used_bytes = 0
    current_date_str = datetime.now().strftime("%Y-%m-%d")

    db_changed = False
    cmds_to_sync = []

    for uname, info in db.items():
        if not isinstance(info, dict): continue
        user_node = info.get('node')
        user_group = info.get('group')
        
        is_active_node = (user_node == node_id)
        belongs_to_node = is_active_node
        
        # သတ်မှတ်ထားသော Active Node မဟုတ်ပါက၊ ၎င်း၏ Group ထဲတွင် ဤဆာဗာ ပါမပါ စစ်ဆေးမည်
        if not belongs_to_node and user_group and user_group in auto_groups:
            if node_id in auto_groups[user_group].get("nodes", {}):
                belongs_to_node = True

        # 🚀 ဤဆာဗာ (သို့) ဤဆာဗာပါဝင်သော Group မှ User ဖြစ်လျှင် မျက်နှာပြင်တွင် ပြပေးမည်
        if belongs_to_node:
            uid = info.get('uuid')
            port = info.get('port')
            proto = info.get('protocol', 'v2')
            display = get_display_name(uname, info)
            safe_u = urllib.parse.quote(display)

            if proto == 'v2':
                expected_key = f"vless://{uid}@{node_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
                cmd = f"/usr/local/bin/v2ray-node-add-vless {shlex.quote(str(display))} {shlex.quote(str(uid))}"
            else:
                credentials = f"chacha20-ietf-poly1305:{uid}"
                b64_creds = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8').rstrip('=')
                expected_key = f"ss://{b64_creds}@{node_ip}:{port}#{safe_u}"
                cmd = get_safe_add_out_cmd(display, uid, port)
                
            # Database တွင် အပြောင်းအလဲလုပ်ခြင်းကို Active ဖြစ်သော ပင်မဆာဗာ (၁) ခုတည်းအတွက်သာ လုပ်မည်
            if is_active_node:
                if info.get('key') != expected_key:
                    info['key'] = expected_key
                    db_changed = True
                    if not info.get('is_blocked', False):
                        cmds_to_sync.append(cmd)
            
            # 🚀 UI တွင်ပြရန်အတွက် သီးသန့် Copy ကူး၍ ပြင်ဆင်မည် (Main DB အား မထိခိုက်စေရန်)
            display_info = info.copy()
            display_info['used_bytes'] = float(display_info.get('used_bytes', 0))
            display_info['total_gb'] = float(display_info.get('total_gb', 0))
            display_info['used_gb_str'] = f"{(display_info['used_bytes'] / (1024**3)):.2f}"
            display_info['db_key'] = uname
            display_info['username'] = display

            display_info['actual_key'] = expected_key

            display_info['is_active'] = uname in node_active_users and not display_info.get('is_blocked')
            display_info['protocol_label'] = "VLESS" if display_info.get('protocol') == 'v2' else "Outline SS"
            
            exp_str = display_info.get('expire_date')
            is_expired = True if (exp_str and current_date_str > exp_str) else False
            
            if is_expired: display_info['status_label'] = "Expired"
            elif display_info.get('is_blocked'): display_info['status_label'] = "Blocked"
            elif display_info['is_active']: display_info['status_label'] = "Online"
            else: display_info['status_label'] = "Offline"
                
            if not is_active_node:
                display_info['status_label'] += " (Synced)"
                
            users.append(display_info)
            
            # GB အသုံးပြုမှုကို Active ဖြစ်သော ဆာဗာအတွက်သာ ပေါင်းထည့်မည် (၂ ခါ မထပ်စေရန်)
            if is_active_node:
                node_used_bytes += display_info['used_bytes']
            
    if db_changed:
        with db_lock:
            with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)
    if cmds_to_sync and node_ip:
        prefix = "systemctl() { true; }; export -f systemctl; "
        suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
        execute_ssh_bg(node_ip, [prefix + " ; ".join(cmds_to_sync) + suffix])
            
    ninfo = ndb.get(node_id, {})
    limit_tb = float(ninfo.get("limit_tb", 0))
    used_gb = node_used_bytes / (1024**3)
    limit_gb = limit_tb * 1024
    is_alarm = limit_tb > 0 and used_gb >= limit_gb
    health = ninfo.get("health", "green")
            
    other_nodes = [nid for nid in nodes.keys() if nid != node_id]
    
    node_ping_ms = measure_ping_latency_ms(node_ip)
    node_ping_status = "online" if node_ping_ms is not None else "offline"
    node_backups = list_backups(BACKUP_DIR).get("node_backups", {}).get(node_id, [])

    return render_template(
        'node.html',
        node_id=node_id,
        node_name=node_info.get('name', ''),
        node_ip=node_ip,
        users=users,
        other_nodes=other_nodes,
        config=config,
        used_gb=used_gb,
        limit_tb=limit_tb,
        is_alarm=is_alarm,
        health=health,
        node_ping_ms=node_ping_ms,
        node_ping_status=node_ping_status,
        node_backups=node_backups
    )

@app.route('/add_node', methods=['POST'])
def add_node():
    n_id = request.form.get('node_id', '').strip().replace(" ", "_")
    n_name = request.form.get('node_name', '').strip()
    n_ip = request.form.get('node_ip', '').strip()
    ssh_user = request.form.get('ssh_username', 'root').strip() or 'root'
    ssh_password = request.form.get('ssh_password', '')
    
    if n_id and n_name and n_ip:
        nodes = get_all_servers()
        if _node_id_exists_ci(n_id, nodes):
            return f"<script>alert('Error: Node ID [{n_id}] already exists!'); window.history.back();</script>"
        ok, msg = install_master_key_with_password(n_ip, ssh_user, ssh_password)
        if not ok:
            alert_msg = json.dumps(f"SSH key setup failed: {msg}")
            log_activity("Add Custom Node SSH Key Failed", f"node={n_id} ip={n_ip} error={str(msg)[:140]}", "error")
            return f"<script>alert({alert_msg}); window.history.back();</script>"
            
        if not os.path.exists(NODES_LIST):
            with open(NODES_LIST, 'w') as f: 
                f.write("")
                
        with open(NODES_LIST, 'a') as f: 
            f.write(f"\n{n_id}|{n_name}|{n_ip}")
        log_activity("Add Custom Node", f"node={n_id} name={n_name} ip={n_ip} ssh_key_setup={msg}", "success")
            
    return redirect(f"/node/{n_id}?newly_added={n_id}")

@app.route('/delete_node/<node_id>', methods=['POST'])
def delete_node(node_id):
    # Stop xray on matching node IP (case-insensitive node id match).
    node_ip = ""
    for nid, ninfo in get_all_servers().items():
        if _node_id_equals(nid, node_id):
            node_ip = str((ninfo or {}).get('ip', '')).strip()
            break
    if node_ip:
        execute_ssh_bg(node_ip, ["systemctl stop xray"])

    removed = _hard_remove_node_references(node_id, remove_from_nodes_list=True, remove_backups=False)
    scope = "auto-group" if removed.get("groups", 0) > 0 else "custom"
    log_activity(
        "Delete Node",
        f"node={node_id} scope={scope} users_removed={removed.get('users', 0)} groups_removed={removed.get('groups', 0)} ndb_removed={removed.get('nodes_db', 0)}",
        "warning"
    )
    return redirect(url_for('dashboard'))

@app.route('/replace_id/<current_id>', methods=['POST'])
def replace_id(current_id):
    old_id = request.form.get('old_id', '').strip()
    nodes = get_all_servers()
    if current_id not in nodes or not old_id: 
        return redirect(f'/node/{current_id}')
    
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f: 
            lines = f.readlines()
        with open(NODES_LIST, 'w') as f:
            for line in lines:
                if line.strip():
                    if line.startswith(f"{current_id}|") or line.startswith(f"{current_id} "):
                        if '|' in line:
                            parts = line.split('|')
                            f.write(f"{old_id}|{parts[1]}|{parts[2]}\n")
                        else:
                            parts = line.rsplit(' ', 1)
                            f.write(f"{old_id} {parts[1]}\n")
                    else: 
                        f.write(line)
                    
    groups = load_auto_groups()
    replaced_group_id = ""
    for gid, gdata in groups.items():
        if current_id in gdata.get("nodes", {}):
            ndata = gdata["nodes"][current_id]
            del groups[gid]["nodes"][current_id]
            groups[gid]["nodes"][old_id] = ndata
            save_auto_groups(groups)
            replaced_group_id = gid
            break
            
    new_ip = get_target_ip(old_id)
    if new_ip:
        with db_lock:
            db = {}
            if os.path.exists(USERS_DB):
                with open(USERS_DB, 'r') as f: db = json.load(f)
            
            cmds_to_sync = []
            db_changed = False
            
            for uname, uinfo in db.items():
                if isinstance(uinfo, dict) and uinfo.get('node') == current_id:
                    uinfo['node'] = old_id
                    uid = uinfo.get('uuid')
                    port = uinfo.get('port')
                    proto = uinfo.get('protocol', 'v2')
                    safe_u = urllib.parse.quote(uname)
                    
                    if proto == 'v2':
                        uinfo['key'] = f"vless://{uid}@{new_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
                        cmd = f"/usr/local/bin/v2ray-node-add-vless {shlex.quote(str(uname))} {shlex.quote(str(uid))}"
                    else:
                        credentials = f"chacha20-ietf-poly1305:{uid}"
                        b64_creds = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8').rstrip('=')
                        uinfo['key'] = f"ss://{b64_creds}@{new_ip}:{port}#{safe_u}"
                        cmd = get_safe_add_out_cmd(uname, uid, port)
                        
                    db_changed = True
                    if not uinfo.get('is_blocked', False):
                        cmds_to_sync.append(cmd)
                        
            if db_changed:
                with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)
                
        if cmds_to_sync:
            prefix = "systemctl() { true; }; export -f systemctl; "
            suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
            execute_ssh_bg(new_ip, [prefix + " ; ".join(cmds_to_sync) + suffix])
        if replaced_group_id:
            threading.Thread(
                target=sync_new_node_to_subpanel,
                args=(replaced_group_id, old_id, str(new_ip).strip()),
                daemon=True
            ).start()
            
    return redirect(f'/node/{old_id}')

@app.route('/api/check_ssh/<node_id>')
def check_ssh(node_id):
    ip = get_target_ip(node_id)
    if not ip: 
        return jsonify({"status": "error", "msg": "IP not found in nodes list."})
    
    try:
        cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{ip} 'echo ok'"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if "ok" in res.stdout: 
            return jsonify({"status": "success"})
        else:
            return jsonify({"status": "error", "msg": res.stderr.strip()})
    except Exception as e: 
        return jsonify({"status": "error", "msg": str(e)})

@app.route('/api/check_xray/<node_id>')
def check_xray(node_id):
    ip = get_target_ip(node_id)
    if not ip: 
        return jsonify({"status": "inactive"})
        
    try:
        res = subprocess.run(f"ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@{ip} 'systemctl is-active xray'", shell=True, capture_output=True, text=True)
        if "active" in res.stdout.strip().lower(): 
            return jsonify({"status": "active"})
    except: 
        pass
    return jsonify({"status": "inactive"})

@app.route('/api/ping/<node_id>')
def api_ping(node_id):
    ip = get_target_ip(node_id)
    if not ip:
        return jsonify({"status": "offline", "msg": "IP not found"})
    latency_ms = measure_ping_latency_ms(ip)
    if latency_ms is None:
        return jsonify({"status": "offline"})
    return jsonify({"status": "online", "latency_ms": latency_ms})


def _probe_node_xray_health(node_id, node_info):
    ip = str((node_info or {}).get("ip", "")).strip()
    name = str((node_info or {}).get("name", node_id)).strip() or str(node_id)
    base = {"id": str(node_id), "name": name, "ip": ip}
    if not ip:
        base["status"] = "invalid"
        base["reason"] = "missing_ip"
        return base

    cmd = (
        f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{ip} "
        "'s=$(systemctl is-active xray 2>/dev/null || true); "
        "if [ -n \"$s\" ]; then echo \"$s\"; "
        "elif pgrep -x xray >/dev/null 2>&1; then echo active; "
        "else echo inactive; fi'"
    )
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=8)
        out = str(res.stdout or "").strip().lower()
        err = str(res.stderr or "").strip().lower()
        if out == "active":
            base["status"] = "active"
            return base
        if out in ("inactive", "failed", "activating", "deactivating", "unknown"):
            base["status"] = "inactive"
            base["reason"] = out
            return base
        if (
            res.returncode == 255
            or "permission denied" in err
            or "no route to host" in err
            or "connection refused" in err
            or "connection timed out" in err
            or "operation timed out" in err
        ):
            base["status"] = "unreachable"
            base["reason"] = "ssh_unreachable"
            return base
        base["status"] = "inactive"
        base["reason"] = out or "unknown"
        return base
    except Exception:
        base["status"] = "unreachable"
        base["reason"] = "timeout_or_error"
        return base


@app.route('/settings/node-health')
def settings_node_health():
    all_nodes = get_all_servers()
    cfg = load_config()
    monitor_skip_set = {
        str(x).strip().lower()
        for x in (cfg.get("monitor_skip_nodes", []) or [])
        if str(x).strip()
    }
    items = []
    if not all_nodes:
        return jsonify({
            "status": "ok",
            "checked": 0,
            "inactive_count": 0,
            "inactive_nodes": [],
            "nodes": []
        })

    max_workers = min(12, max(1, len(all_nodes)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_probe_node_xray_health, node_id, ninfo): node_id
            for node_id, ninfo in all_nodes.items()
        }
        for fut in as_completed(futures):
            try:
                items.append(fut.result())
            except Exception:
                node_id = str(futures[fut])
                items.append({
                    "id": node_id,
                    "name": node_id,
                    "ip": "",
                    "status": "unreachable",
                    "reason": "probe_failed"
                })

    items.sort(key=lambda x: str(x.get("id", "")).lower())
    for row in items:
        row["monitor_skipped"] = str(row.get("id", "")).strip().lower() in monitor_skip_set
    inactive_nodes = [x for x in items if str(x.get("status")) != "active"]
    return jsonify({
        "status": "ok",
        "checked": len(items),
        "inactive_count": len(inactive_nodes),
        "inactive_nodes": inactive_nodes,
        "nodes": items
    })


@app.route('/api/settings/monitor-skip/<node_id>', methods=['POST'])
def api_settings_monitor_skip(node_id):
    node_id = str(node_id or "").strip()
    if not node_id:
        return jsonify({"status": "error", "msg": "node_id required"}), 400

    all_nodes = get_all_servers()
    node_exists = any(str(nid).strip().lower() == node_id.lower() for nid in all_nodes.keys())
    if not node_exists:
        return jsonify({"status": "error", "msg": "Node not found"}), 404

    cfg = load_config()
    arr = cfg.get("monitor_skip_nodes", [])
    if not isinstance(arr, list):
        arr = []

    node_norm = node_id.lower()
    existing = {str(x).strip().lower(): str(x).strip() for x in arr if str(x).strip()}
    action = str(request.args.get("action", "toggle")).strip().lower()

    if action == "enable":
        existing[node_norm] = node_id
    elif action == "disable":
        existing.pop(node_norm, None)
    else:
        if node_norm in existing:
            existing.pop(node_norm, None)
        else:
            existing[node_norm] = node_id

    cfg["monitor_skip_nodes"] = list(existing.values())
    save_config(cfg)
    skipped = node_norm in {str(x).strip().lower() for x in cfg.get("monitor_skip_nodes", [])}
    log_activity("Monitor Skip Toggle", f"node={node_id} skipped={skipped}", "info")
    return jsonify({"status": "ok", "node_id": node_id, "monitor_skipped": skipped})

@app.route('/api/search_all')
def api_search_all():
    q = str(request.args.get('q', '')).strip()
    if len(q) < 1:
        return jsonify({"status": "ok", "query": q, "groups": [], "nodes": [], "users": []})

    ql = q.lower()
    groups = load_auto_groups()
    all_nodes = get_all_servers()
    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f:
                    db = json.load(f)
            except Exception:
                db = {}

    group_results = []
    for gid, gdata in groups.items():
        gname = str(gdata.get("name", gid))
        if ql in gid.lower() or ql in gname.lower():
            group_results.append({
                "id": gid,
                "name": gname,
                "url": f"/group/{gid}",
                "node_count": len(gdata.get("nodes", {}))
            })
    group_results = group_results[:20]

    node_results = []
    for nid, ninfo in all_nodes.items():
        nname = str(ninfo.get("name", nid))
        nip = str(ninfo.get("ip", ""))
        if ql in nid.lower() or ql in nname.lower() or ql in nip.lower():
            node_results.append({
                "id": nid,
                "name": nname,
                "ip": nip,
                "url": f"/node/{nid}"
            })
    node_results = node_results[:30]

    user_results = []
    for uname, uinfo in db.items():
        if not isinstance(uinfo, dict):
            continue
        display = get_display_name(uname, uinfo)
        node_id = str(uinfo.get("node", "")).strip()
        group_id = str(uinfo.get("group", "")).strip()
        text_blob = " ".join([
            display,
            uname,
            str(uinfo.get("key_id", "")),
            str(uinfo.get("protocol", "")),
            node_id,
            group_id,
            str(uinfo.get("port", ""))
        ]).lower()
        if ql in text_blob:
            used_gb = float(uinfo.get("used_bytes", 0) or 0) / (1024 ** 3)
            total_gb = float(uinfo.get("total_gb", 0) or 0)
            user_results.append({
                "username": display,
                "node": node_id,
                "group": group_id,
                "blocked": bool(uinfo.get("is_blocked", False)),
                "used_gb": round(used_gb, 2),
                "total_gb": total_gb,
                "url": f"/node/{node_id}"
            })
    user_results = user_results[:80]

    return jsonify({
        "status": "ok",
        "query": q,
        "groups": group_results,
        "nodes": node_results,
        "users": user_results
    })


@app.route('/api/internal/monitor-status')
def api_internal_monitor_status():
    return jsonify({"status": "ok", "monitor": get_monitor_status()})


@app.route('/api/internal/sync-new-server-status')
def api_internal_sync_new_server_status():
    group_id = str(request.args.get("group_id", "")).strip()
    info = _get_sync_new_server_status()
    if group_id:
        info["matches_group"] = str(info.get("last_group_id", "")).strip().lower() == group_id.lower()
    return jsonify({"status": "ok", "sync_new_server": info})

@app.route('/api/node-active-users')
def api_node_active_users():
    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f: db = json.load(f)
    active_users = check_live_status(db)
    groups = load_auto_groups()
    all_servers = get_all_servers()

    node_data = {}
    for uname, uinfo in db.items():
        if not isinstance(uinfo, dict): continue
        nid = uinfo.get('node')
        if not nid: continue
        if nid not in node_data:
            node_data[nid] = {"nodeId": nid, "totalUsers": 0, "activeUsers": 0, "users": []}
        node_data[nid]["totalUsers"] += 1
        nip = str((all_servers.get(nid, {}) or {}).get('ip', '')).strip()
        online_ips = uinfo.get('online_on_ips', [])
        is_active = bool(nip and isinstance(online_ips, list) and nip in online_ips and not uinfo.get('is_blocked'))
        if is_active:
            node_data[nid]["activeUsers"] += 1
        node_data[nid]["users"].append({
            "username": get_display_name(uname, uinfo),
            "isActive": is_active,
            "isBlocked": bool(uinfo.get('is_blocked')),
            "usedGB": round(float(uinfo.get('used_bytes', 0)) / (1024**3), 4),
            "totalGB": float(uinfo.get('total_gb', 0)),
            "node": nid,
            "group": uinfo.get('group', '')
        })

    for nid in node_data:
        ninfo = all_servers.get(nid, {})
        node_data[nid]["nodeName"] = ninfo.get('name', nid)
        node_data[nid]["nodeIp"] = ninfo.get('ip', '')

    return jsonify({"success": True, "nodes": node_data})


@app.route('/api/stats/<node_id>')
def api_stats(node_id):
    ip = get_target_ip(node_id)
    if not ip: 
        return jsonify({"status": "error"})
        
    try:
        res = subprocess.run(f"ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no root@{ip} \"/usr/local/bin/xray api statsquery --server=127.0.0.1:10085\"", shell=True, capture_output=True, text=True)
        stats = json.loads(res.stdout).get("stat", [])
        data = {}
        for s in stats:
            p = s.get("name", "").split(">>>")
            v = s.get("value", 0)
            if len(p) >= 4:
                if p[0] == "user": 
                    data[p[1]] = data.get(p[1], 0) + v
                elif p[0] == "inbound" and p[1].startswith("out-"): 
                    data[p[1][4:]] = data.get(p[1][4:], 0) + v
        return jsonify({"status": "ok", "data": data})
    except: 
        return jsonify({"status": "error"})

def _run_node_install_script(node_id, ip_str):
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "install_node.sh")
    if not os.path.exists(script_path):
        return False, f"install script not found: {script_path}"

    with open(script_path, 'r', encoding='utf-8') as f:
        install_script = f.read()

    install_res = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=20", "-o", "StrictHostKeyChecking=no", f"root@{ip_str}", "bash -s"],
        input=install_script,
        text=True,
        capture_output=True,
        timeout=480
    )
    if install_res.returncode != 0:
        err = (install_res.stderr or install_res.stdout or "install failed").strip()
        return False, err[:500]

    verify_cmd = (
        "command -v /usr/local/bin/xray >/dev/null 2>&1 && "
        "command -v /usr/local/bin/v2ray-node-add-out >/dev/null 2>&1 && "
        "command -v /usr/local/bin/v2ray-node-add-vless >/dev/null 2>&1 && "
        "systemctl is-active --quiet xray"
    )
    verify_res = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=12", "-o", "StrictHostKeyChecking=no", f"root@{ip_str}", verify_cmd],
        capture_output=True,
        text=True,
        timeout=30
    )
    if verify_res.returncode != 0:
        err = (verify_res.stderr or verify_res.stdout or "xray not ready").strip()
        return False, err[:500]
    return True, "ok"


def _reprovision_users_after_reinstall(node_id, node_ip):
    node_norm = str(node_id or "").strip().lower()
    groups = load_auto_groups()
    owner_group_ids = []
    for gid, gdata in groups.items():
        gnodes = (gdata or {}).get("nodes", {})
        if any(_node_id_equals(nid, node_norm) for nid in gnodes.keys()):
            owner_group_ids.append(str(gid))

    with db_lock:
        if not os.path.exists(USERS_DB):
            return 0, owner_group_ids
        try:
            with open(USERS_DB, 'r') as f:
                db = json.load(f)
        except Exception:
            db = {}

    cmds = []
    for uname, uinfo in db.items():
        if not isinstance(uinfo, dict):
            continue
        if bool(uinfo.get('is_blocked', False)):
            continue
        user_node = str(uinfo.get('node', '')).strip().lower()
        user_group = str(uinfo.get('group', '')).strip()
        in_scope = (user_node == node_norm) or (user_group in owner_group_ids)
        if not in_scope:
            continue

        uid = str(uinfo.get('uuid', '')).strip()
        proto = str(uinfo.get('protocol', 'out')).strip()
        if not uid:
            continue
        if proto == 'v2':
            cmd = f"/usr/local/bin/v2ray-node-add-vless {shlex.quote(str(uname))} {shlex.quote(str(uid))}"
        else:
            port = str(uinfo.get('port', '')).strip()
            if not port:
                continue
            cmd = get_safe_add_out_cmd(uname, uid, port)
        cmds.append(cmd)

    if not cmds:
        return 0, owner_group_ids

    chunk_size = 80
    for i in range(0, len(cmds), chunk_size):
        chunk = cmds[i:i + chunk_size]
        prefix = "systemctl() { true; }; export -f systemctl; "
        suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
        execute_ssh_bg(node_ip, [prefix + " ; ".join(chunk) + suffix])
    return len(cmds), owner_group_ids


def _expected_users_for_node(node_id):
    """Return active DB users that should exist in a node's Xray config."""
    node_norm = str(node_id or "").strip().lower()
    groups = load_auto_groups()
    owner_group_ids = []
    for gid, gdata in groups.items():
        gnodes = (gdata or {}).get("nodes", {})
        if any(_node_id_equals(nid, node_norm) for nid in gnodes.keys()):
            owner_group_ids.append(str(gid))

    with db_lock:
        db = safe_load_json(USERS_DB, {})
        if not isinstance(db, dict):
            db = {}

    expected = []
    for db_key, uinfo in db.items():
        if not isinstance(uinfo, dict) or bool(uinfo.get('is_blocked', False)):
            continue
        user_node = str(uinfo.get('node', '')).strip().lower()
        user_group = str(uinfo.get('group', '')).strip()
        if user_node == node_norm or user_group in owner_group_ids:
            expected.append((db_key, uinfo))
    return expected, owner_group_ids


def _fetch_node_xray_config(ip_str):
    try:
        res = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=12", "-o", "StrictHostKeyChecking=no", f"root@{ip_str}", "cat /usr/local/etc/xray/config.json"],
            capture_output=True,
            text=True,
            timeout=25
        )
        if res.returncode != 0:
            return None, (res.stderr or res.stdout or "ssh failed")[:500]
        return json.loads(res.stdout or "{}"), ""
    except Exception as e:
        return None, str(e)[:500]


def _audit_node_keys(node_id):
    ip = get_target_ip(node_id)
    if not ip:
        return {"success": False, "error": "Node IP not found"}, 404
    ip_str = str(ip).strip()
    expected, owner_groups = _expected_users_for_node(node_id)
    cfg, err = _fetch_node_xray_config(ip_str)
    if cfg is None:
        return {"success": False, "error": err or "Unable to read node config"}, 500

    inbounds = cfg.get("inbounds", []) if isinstance(cfg, dict) else []
    clients_by_id = set()
    inbound_tags = set()
    inbound_ports = set()
    ss_passwords = set()
    for ib in inbounds:
        if not isinstance(ib, dict):
            continue
        tag = str(ib.get("tag", "")).strip()
        port = str(ib.get("port", "")).strip()
        if tag:
            inbound_tags.add(tag)
        if port:
            inbound_ports.add(port)
        settings = ib.get("settings") or {}
        if isinstance(settings, dict):
            for c in settings.get("clients", []) or []:
                if isinstance(c, dict) and c.get("id"):
                    clients_by_id.add(str(c.get("id")).strip())
            if settings.get("password"):
                ss_passwords.add(str(settings.get("password")).strip())

    missing = []
    present = 0
    for db_key, uinfo in expected:
        display = get_display_name(db_key, uinfo)
        uid = str(uinfo.get("uuid", "")).strip()
        proto = str(uinfo.get("protocol", "out")).strip()
        port = str(uinfo.get("port", "")).strip()
        exists = False
        if proto == "v2":
            exists = bool(uid and uid in clients_by_id)
        else:
            exists = (f"out-{display}" in inbound_tags) or (port and port in inbound_ports) or (uid and uid in ss_passwords)
        if exists:
            present += 1
        else:
            missing.append({"db_key": db_key, "username": display, "protocol": proto, "port": port})

    return {
        "success": True,
        "node_id": node_id,
        "node_ip": ip_str,
        "owner_groups": owner_groups,
        "expected": len(expected),
        "present": present,
        "missing_count": len(missing),
        "missing": missing[:300],
    }, 200


@app.route('/api/audit_node_keys/<node_id>')
def api_audit_node_keys(node_id):
    payload, code = _audit_node_keys(node_id)
    return jsonify(payload), code


@app.route('/repair_node_keys/<node_id>', methods=['POST'])
def repair_node_keys(node_id):
    ip = get_target_ip(node_id)
    if not ip:
        log_activity("Repair Node Keys Failed", f"node={node_id} error=ip_not_found", "error")
        return redirect(request.referrer or f"/node/{node_id}")
    count, owner_groups = _reprovision_users_after_reinstall(node_id, str(ip).strip())
    for gid in owner_groups:
        threading.Thread(target=sync_new_node_to_subpanel, args=(gid, node_id, str(ip).strip()), daemon=True).start()
    log_activity("Repair Node Keys", f"node={node_id} users_reprovisioned={count} groups_synced={len(owner_groups)}", "warning")
    return redirect(request.referrer or f"/node/{node_id}")

@app.route('/install_node/<node_id>', methods=['POST'])
def install_node_action(node_id):
    wants_json = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or \
        'application/json' in (request.headers.get('Accept') or '')

    ip = get_target_ip(node_id)
    if not ip:
        if wants_json:
            return jsonify({"success": False, "error": "Node IP not found"}), 404
        return redirect(request.referrer or url_for('dashboard'))

    ip_str = str(ip).strip()
    try:
        ok, err = _run_node_install_script(node_id, ip_str)
        if not ok:
            log_activity("Install Xray Failed", f"node={node_id} error={err[:140]}", "error")
            if wants_json:
                return jsonify({"success": False, "error": err[:500]}), 500
            return redirect(request.referrer or url_for('dashboard'))

        log_activity("Install Xray Success", f"node={node_id}", "success")
        if wants_json:
            return jsonify({"success": True, "message": "Xray installed and ready"})
        return redirect(request.referrer or url_for('dashboard'))
    except subprocess.TimeoutExpired:
        log_activity("Install Xray Timeout", f"node={node_id}", "error")
        if wants_json:
            return jsonify({"success": False, "error": "Install timeout"}), 504
        return redirect(request.referrer or url_for('dashboard'))
    except Exception as e:
        log_activity("Install Xray Error", f"node={node_id} error={str(e)[:140]}", "error")
        if wants_json:
            return jsonify({"success": False, "error": str(e)}), 500
        return redirect(request.referrer or url_for('dashboard'))

@app.route('/reinstall_node/<node_id>', methods=['POST'])
def reinstall_node_action(node_id):
    ip = get_target_ip(node_id)
    if not ip:
        return redirect(request.referrer or url_for('dashboard'))

    ip_str = str(ip).strip()
    try:
        ok, err = _run_node_install_script(node_id, ip_str)
        if not ok:
            log_activity("Reinstall Node Failed", f"node={node_id} error={err[:140]}", "error")
            return redirect(request.referrer or f"/node/{node_id}")

        reprovisioned, owner_groups = _reprovision_users_after_reinstall(node_id, ip_str)
        for gid in owner_groups:
            threading.Thread(
                target=sync_new_node_to_subpanel,
                args=(gid, node_id, ip_str),
                daemon=True
            ).start()

        log_activity(
            "Reinstall Node Success",
            f"node={node_id} users_reprovisioned={reprovisioned} groups_synced={len(owner_groups)}",
            "success"
        )
    except Exception as e:
        log_activity("Reinstall Node Error", f"node={node_id} error={str(e)[:140]}", "error")
    return redirect(request.referrer or f"/node/{node_id}")

@app.route('/restart_xray/<node_id>', methods=['POST'])
def restart_xray_action(node_id):
    ip = get_target_ip(node_id)
    if ip: 
        execute_ssh_bg(ip, ["systemctl restart xray"])
    log_activity("Restart Xray", f"node={node_id}", "info")
    return redirect(request.referrer)

@app.route('/hard_reset_node_keys/<node_id>', methods=['POST'])
def hard_reset_node_keys(node_id):
    ip = get_target_ip(node_id)
    if not ip:
        return redirect(request.referrer or url_for('dashboard'))

    # Emergency destructive action:
    # - remove all SS out-* inbounds
    # - clear all VLESS clients from vless-inbound
    # - cleanup related UFW rules
    cleanup_cmd = (
        "bash -lc '"
        "CFG=/usr/local/etc/xray/config.json; "
        "[ -f \"$CFG\" ] || exit 1; "
        "for p in $(jq -r '.inbounds[]? | select((.tag//\"\")|startswith(\"out-\")) | .port // empty' \"$CFG\"); do "
        "ufw delete allow ${p}/tcp >/dev/null 2>&1 || true; "
        "ufw delete allow ${p}/udp >/dev/null 2>&1 || true; "
        "done; "
        "python3 - <<\"PY\"\n"
        "import json\n"
        "p='/usr/local/etc/xray/config.json'\n"
        "with open(p,'r') as f:\n"
        "    d=json.load(f)\n"
        "d['inbounds']=[i for i in d.get('inbounds',[]) if not str(i.get('tag','')).startswith('out-')]\n"
        "for i in d.get('inbounds',[]):\n"
        "    if str(i.get('tag','')) == 'vless-inbound':\n"
        "        s=i.get('settings') or {}\n"
        "        if isinstance(s,dict) and isinstance(s.get('clients'),list):\n"
        "            s['clients']=[]\n"
        "            i['settings']=s\n"
        "with open(p,'w') as f:\n"
        "    json.dump(d,f,indent=4)\n"
        "PY\n"
        "systemctl reset-failed xray >/dev/null 2>&1 || true; "
        "systemctl restart xray"
        "'"
    )
    execute_ssh_bg(str(ip).strip(), [cleanup_cmd])
    log_activity("Hard Reset Node Keys", f"node={node_id}", "warning")
    return redirect(request.referrer or f"/node/{node_id}")

@app.route('/toggle_node/<node_id>', methods=['POST'])
def toggle_node(node_id):
    config = load_config()
    if 'disabled_nodes' not in config: 
        config['disabled_nodes'] = []
    
    ip = get_target_ip(node_id)
    
    if node_id in config['disabled_nodes']:
        config['disabled_nodes'].remove(node_id)
        if ip: execute_ssh_bg(ip, ["systemctl start xray"])
        log_activity("Enable Node", f"node={node_id}", "success")
    else:
        config['disabled_nodes'].append(node_id)
        if ip: execute_ssh_bg(ip, ["systemctl stop xray"])
        log_activity("Disable Node", f"node={node_id}", "warning")
        
    save_config(config)
    return redirect(request.referrer)

@app.route('/add_user_manual', methods=['POST'])
def add_user_manual():
    nid = request.form.get('node_id')
    nip = get_target_ip(nid)
    if not nip: 
        return redirect(f'/node/{nid}')
    
    gid = ""
    groups = load_auto_groups()
    for g_id, gdata in groups.items():
        if nid in gdata.get("nodes", {}): 
            gid = g_id
            break

    mode = request.form.get('creation_mode', 'single')
    raw_usernames = []
    if mode == 'single': 
        raw_usernames = [request.form.get('single_username', '')]
    elif mode == 'list': 
        raw_usernames = re.split(r'[,\n\r]+', request.form.get('list_usernames', ''))
    elif mode == 'pattern':
        base = request.form.get('base_name', '').strip()
        try: start = int(request.form.get('start_num', 1))
        except: start = 1
        try: qty = int(request.form.get('qty', 1))
        except: qty = 1
        raw_usernames = [f"{base}{start+i}" for i in range(qty)]

    try: gb = float(request.form.get('total_gb') or 0)
    except: gb = 0.0
    try: days = int(request.form.get('expire_days') or 30)
    except: days = 30
    
    proto = request.form.get('protocol', 'v2')
    
    success, msg = add_keys(nid, gid, raw_usernames, gb, days, proto, is_auto=False)
    if not success: 
        return f"<script>alert('{msg}'); window.history.back();</script>"
    log_activity("Add Manual Users", f"node={nid} mode={mode} protocol={proto}", "success")
        
    return redirect(request.referrer)

@app.route('/toggle_user/<username>', methods=['POST'])
def toggle_user(username):
    toggle_key(username)
    log_activity("Toggle User Status", f"user={username}", "warning")
    return redirect(request.referrer)

@app.route('/switch_user_node/<username>', methods=['POST'])
def switch_user_node(username):
    target_node_raw = request.form.get('target_node', '').strip()
    if not target_node_raw:
        return redirect(request.referrer)

    def _norm(s):
        return str(s or "").strip().lower()

    # Resolve node by id/name in a tolerant way (case-insensitive, [AUTO] name support).
    target_node = None
    raw_n = _norm(target_node_raw)
    for nid, ndata in get_all_servers().items():
        nid_n = _norm(nid)
        name = str(ndata.get('name', '')).strip()
        name_n = _norm(name)
        name_no_auto = name
        if name_no_auto.startswith("[AUTO]"):
            name_no_auto = name_no_auto.replace("[AUTO]", "", 1).strip()
        name_no_auto_n = _norm(name_no_auto)
        if raw_n in {nid_n, name_n, name_no_auto_n}:
            target_node = nid
            break

    if not target_node:
        return redirect(request.referrer)

    with db_lock:
        db = {}
        if not os.path.exists(USERS_DB):
            return redirect(request.referrer)
        with open(USERS_DB, 'r') as f:
            db = json.load(f)

        if username not in db or not isinstance(db.get(username), dict):
            return redirect(request.referrer)

        uinfo = db[username]
        old_node = uinfo.get('node')
        if old_node == target_node:
            return redirect(request.referrer)

        group_id = uinfo.get('group')
        if group_id:
            groups = load_auto_groups()
            g_nodes = groups.get(group_id, {}).get("nodes", {})
            g_nodes_norm = {str(nid).strip().lower(): nid for nid in g_nodes.keys()}
            if target_node not in g_nodes:
                target_node = g_nodes_norm.get(str(target_node).strip().lower(), target_node)
            if target_node not in g_nodes:
                return redirect(request.referrer)

        new_ip = get_target_ip(target_node)
        if not new_ip:
            return redirect(request.referrer)
        new_ip = str(new_ip).strip()

        old_ip = get_target_ip(old_node)
        old_ip = str(old_ip).strip() if old_ip else None

        uid = uinfo.get('uuid')
        port = uinfo.get('port')
        proto = uinfo.get('protocol', 'out')
        display = get_display_name(username, uinfo)
        safe_u = urllib.parse.quote(display)
        is_blocked = uinfo.get('is_blocked', False)

        if old_ip:
            try:
                cmd_stats = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{old_ip} '/usr/local/bin/xray api statsquery --server=127.0.0.1:10085'"
                res = subprocess.run(cmd_stats, shell=True, capture_output=True, text=True, timeout=8)
                if res.stdout:
                    stats = json.loads(res.stdout).get("stat", [])
                    current_val = 0.0
                    for s in stats:
                        p = s.get("name", "").split(">>>")
                        if len(p) >= 4 and p[0] == "user" and p[1] == display:
                            current_val += float(s.get("value", 0))

                    last_val = float(uinfo.get('last_raw_bytes', 0.0))
                    if current_val > last_val:
                        uinfo['used_bytes'] = float(uinfo.get('used_bytes', 0)) + (current_val - last_val)
                    elif current_val < last_val and current_val > 0:
                        uinfo['used_bytes'] = float(uinfo.get('used_bytes', 0)) + current_val
            except Exception:
                pass

        uinfo['node'] = target_node
        if proto == 'v2':
            uinfo['key'] = f"vless://{uid}@{new_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
        else:
            b64_creds = base64.urlsafe_b64encode(f"chacha20-ietf-poly1305:{uid}".encode('utf-8')).decode('utf-8').rstrip('=')
            uinfo['key'] = f"ss://{b64_creds}@{new_ip}:{port}#{safe_u}"
        uinfo['last_raw_bytes'] = 0

        with open(USERS_DB, 'w') as f:
            json.dump(db, f, indent=4)

    log_activity("Switch User Node", f"user={display} from={old_node} to={target_node}", "info")

    return redirect(request.referrer or url_for('dashboard'))

@app.route('/edit_user/<username>', methods=['POST'])
def edit_user_route(username):
    try: gb = float(request.form.get('total_gb') or 0)
    except: gb = None
    exp = request.form.get('expire_date', '')
    new_uuid = request.form.get('uuid', '').strip()
    
    edit_key(username, gb, exp)
    
    if new_uuid:
        with db_lock:
            db = {}
            if os.path.exists(USERS_DB):
                with open(USERS_DB, 'r') as f: db = json.load(f)
                
            if username in db:
                uinfo = db[username]
                old_uuid = uinfo.get('uuid') or uinfo.get('password')
                
                if old_uuid and old_uuid != new_uuid:
                    if 'uuid' in uinfo: uinfo['uuid'] = new_uuid
                    elif 'password' in uinfo: uinfo['password'] = new_uuid
                    if 'key' in uinfo and old_uuid in uinfo['key']:
                        uinfo['key'] = uinfo['key'].replace(old_uuid, new_uuid)
                    with open(USERS_DB, 'w') as f: json.dump(db, f)
                    
                    node_id = uinfo.get('node')
                    node_ip = get_target_ip(node_id)
                    if node_ip:
                        cmd = f"sed -i 's/{old_uuid}/{new_uuid}/g' /usr/local/etc/xray/config.json && systemctl restart xray"
                        execute_ssh_bg(node_ip, [cmd])

    log_activity("Edit User", f"user={username}", "info")
    return redirect(request.referrer)

@app.route('/renew_user/<username>', methods=['POST'])
def renew_user_route(username):
    try: add_gb = float(request.form.get('add_gb') or 50)
    except: add_gb = 50.0
    try: add_days = int(request.form.get('add_days') or 30)
    except: add_days = 30
    renew_key(username, add_gb, add_days)
    log_activity("Renew User", f"user={username} gb={add_gb} days={add_days}", "success")
    return redirect(request.referrer)

@app.route('/delete_user/<username>', methods=['POST'])
def delete_user_route(username):
    delete_key(username)
    log_activity("Delete User", f"user={username}", "warning")
    return redirect(request.referrer)

@app.route('/bulk_delete', methods=['POST'])
def bulk_delete_route():
    usernames = request.form.getlist('usernames')
    bulk_delete_keys(usernames)
    log_activity("Bulk Delete Users", f"count={len(usernames)}", "warning")
    return redirect(request.referrer)

@app.route('/create_node_backup/<node_id>', methods=['POST'])
def create_node_backup(node_id):
    if os.path.exists(USERS_DB):
        with db_lock:
            with open(USERS_DB, 'r') as f:
                db = json.load(f)
        groups = load_auto_groups()
        backup_ref, user_count, folder_label = create_node_backup_snapshot(BACKUP_DIR, node_id, db, groups)
        log_activity("Create Node Backup", f"node={node_id} users={user_count} file={backup_ref} folder={folder_label}", "info")
    return redirect(request.referrer)

@app.route('/download_backup/<path:backup_ref>')
def download_backup(backup_ref):
    path = safe_backup_path(BACKUP_DIR, backup_ref)
    if not path:
        return redirect(request.referrer or url_for('dashboard'))
    if os.path.exists(path): 
        return send_file(path, as_attachment=True)
    return redirect(request.referrer)

@app.route('/delete_backup/<path:backup_ref>', methods=['POST'])
def delete_backup(backup_ref):
    path = safe_backup_path(BACKUP_DIR, backup_ref)
    if not path:
        return redirect(request.referrer or url_for('dashboard'))
    if os.path.exists(path): 
        os.remove(path)
        log_activity("Delete Backup", f"file={backup_ref}", "warning")
    return redirect(request.referrer)

@app.route('/restore_node_backup/<path:backup_ref>', methods=['POST'])
def restore_node_backup(backup_ref):
    path = safe_backup_path(BACKUP_DIR, backup_ref)
    if not path or not os.path.exists(path):
        return redirect(request.referrer or url_for('dashboard'))

    try:
        payload = read_backup_json(path)
    except Exception:
        return redirect(request.referrer or url_for('dashboard'))

    target_node = str(request.form.get('node_id', '')).strip()
    if not target_node and isinstance(payload, dict):
        target_node = str(payload.get('node_id', '')).strip()
    if not target_node:
        return redirect(request.referrer or url_for('dashboard'))

    restore_users = {}
    if isinstance(payload, dict) and payload.get('type') == 'node_backup':
        restore_users = payload.get('users', {}) or {}
    elif isinstance(payload, dict):
        # Legacy node backup format (raw users dict)
        restore_users = payload

    if not isinstance(restore_users, dict):
        return redirect(request.referrer or url_for('dashboard'))

    with db_lock:
        db = {}
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f:
                    db = json.load(f)
            except Exception:
                db = {}

        users_to_delete = [
            uname for uname, info in db.items()
            if isinstance(info, dict) and str(info.get('node', '')).strip() == target_node
        ]
        for uname in users_to_delete:
            del db[uname]

        restored_count = 0
        for uname, uinfo in restore_users.items():
            if not isinstance(uinfo, dict):
                continue
            c = dict(uinfo)
            c['node'] = target_node
            db[uname] = c
            restored_count += 1

        cmds_by_ip = build_keys_and_sync_cmds(db)
        with open(USERS_DB, 'w') as f:
            json.dump(db, f, indent=4)

    for ip, cmds in cmds_by_ip.items():
        prefix = "systemctl() { true; }; export -f systemctl; "
        suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
        execute_ssh_bg(ip, [prefix + " ; ".join(cmds) + suffix])

    log_activity("Restore Node Backup", f"node={target_node} users={restored_count} file={backup_ref}", "success")
    return redirect(request.referrer or f"/node/{target_node}")

@app.route('/purge_node/<node_id>', methods=['POST'])
def purge_node(node_id):
    removed = _hard_remove_node_references(
        node_id,
        remove_from_nodes_list=True,
        remove_backups=True,
        remove_group_links=True
    )
    log_activity(
        "Purge Node Data",
        f"node={node_id} users_removed={removed.get('users', 0)} groups_removed={removed.get('groups', 0)} ndb_removed={removed.get('nodes_db', 0)}",
        "error"
    )
    return redirect(request.referrer)

@app.route('/download_backup_global')
def download_backup_global():
    # Legacy endpoint: keep compatibility.
    if os.path.exists(USERS_DB):
        return send_file(USERS_DB, as_attachment=True, download_name=f"qito_db_backup.json")
    return "No DB found."

def build_full_backup_payload():
    with db_lock:
        users_db = {}
        nodes_db = {}
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f:
                    users_db = json.load(f)
            except Exception:
                users_db = {}
        if os.path.exists(NODES_DB):
            try:
                with open(NODES_DB, 'r') as f:
                    nodes_db = json.load(f)
            except Exception:
                nodes_db = {}

    auto_groups = load_auto_groups()
    cfg = load_config()
    nodes_list_raw = ""
    if os.path.exists(NODES_LIST):
        try:
            with open(NODES_LIST, 'r') as f:
                nodes_list_raw = f.read()
        except Exception:
            nodes_list_raw = ""

    payload = {
        "type": "full_backup",
        "version": 1,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "data": {
            "users_db": users_db,
            "nodes_db": nodes_db,
            "auto_groups": auto_groups,
            "config": cfg,
            "nodes_list": nodes_list_raw,
        }
    }
    return payload, len(users_db)

def create_full_backup_file(source="manual"):
    payload, user_count = build_full_backup_payload()
    backup_ref = create_full_backup_snapshot(BACKUP_DIR, payload)
    backup_path = safe_backup_path(BACKUP_DIR, backup_ref)
    log_activity("Create Full Backup", f"source={source} file={backup_ref} users={user_count}", "info")
    return backup_ref, backup_path, user_count

@app.route('/create_full_backup', methods=['POST'])
def create_full_backup():
    create_full_backup_file("manual_button")
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/save_backup_bot_settings', methods=['POST'])
def save_backup_bot_settings():
    cfg = load_config()
    old_enabled = bool(cfg.get('backup_bot_enabled', False))
    old_token = str(cfg.get('backup_bot_token', '')).strip()
    old_admin = str(cfg.get('backup_bot_admin_id', '')).strip()
    old_interval = float(cfg.get('backup_bot_interval_minutes', 60) or 60)
    cfg['backup_bot_enabled'] = request.form.get('backup_bot_enabled') == 'on'
    cfg['backup_bot_token'] = str(request.form.get('backup_bot_token', '')).strip()
    cfg['backup_bot_admin_id'] = str(request.form.get('backup_bot_admin_id', '')).strip()
    raw_minutes = request.form.get('backup_bot_interval_minutes', None)
    raw_hours = request.form.get('backup_bot_interval_hours', None)
    try:
        if raw_minutes not in (None, ""):
            m = float(raw_minutes)
        elif raw_hours not in (None, ""):
            # Backward-compatible fallback for older dashboard forms.
            m = float(raw_hours) * 60.0
        else:
            m = float(cfg.get('backup_bot_interval_minutes', 60) or 60)
    except Exception:
        m = float(cfg.get('backup_bot_interval_minutes', 60) or 60)
    cfg['backup_bot_interval_minutes'] = max(1.0, m)
    # Keep old config key updated for backward compatibility.
    cfg['backup_bot_interval_hours'] = cfg['backup_bot_interval_minutes'] / 60.0
    changed = (
        old_enabled != cfg['backup_bot_enabled'] or
        old_token != cfg['backup_bot_token'] or
        old_admin != cfg['backup_bot_admin_id'] or
        abs(old_interval - cfg['backup_bot_interval_minutes']) > 1e-9
    )
    if cfg['backup_bot_enabled'] and changed:
        # Trigger next autosend cycle quickly after settings change.
        cfg['backup_bot_last_sent_ts'] = 0
    save_config(cfg)
    log_activity("Save Backup Bot Settings", f"enabled={cfg['backup_bot_enabled']} interval={cfg['backup_bot_interval_minutes']}m", "info")
    return redirect(url_for('dashboard'))


@app.route('/save_external_sync_settings', methods=['POST'])
def save_external_sync_settings():
    from core_monitor import _normalize_sync_base
    cfg = load_config()
    raw_url = str(request.form.get('external_sync_url', '')).strip()
    api_key = str(request.form.get('external_sync_api_key', '')).strip()

    cfg['external_sync_url'] = _normalize_sync_base(raw_url)
    cfg['external_sync_api_key'] = api_key
    cfg.pop('external_new_server_sync_url', None)

    save_config(cfg)
    key_state = "set" if api_key else "empty"
    log_activity("Save External Sync Settings", f"url={cfg['external_sync_url']} api_key={key_state}", "info")
    return redirect(url_for('dashboard'))


@app.route('/save_auth_security_settings', methods=['POST'])
def save_auth_security_settings():
    cfg = load_config()
    cfg, changed = ensure_auth_config(cfg, legacy_password=ADMIN_PASS)
    if changed:
        save_config(cfg)

    current_password = str(request.form.get('current_password', '')).strip()
    new_username = str(request.form.get('auth_username', '')).strip()
    new_password = str(request.form.get('new_password', '')).strip()
    confirm_password = str(request.form.get('confirm_password', '')).strip()
    current_user = str(cfg.get('auth_username', 'admin')).strip() or 'admin'

    wants_login_change = bool(new_username) or bool(new_password) or bool(confirm_password)
    if wants_login_change:
        if not current_password or not verify_login_credentials(cfg, current_user, current_password):
            log_activity("Auth Settings Update Failed", "current password mismatch", "warning")
            return redirect(url_for('dashboard'))
        if new_password or confirm_password:
            if new_password != confirm_password:
                log_activity("Auth Settings Update Failed", "new password confirm mismatch", "warning")
                return redirect(url_for('dashboard'))
            if len(new_password) < 6:
                log_activity("Auth Settings Update Failed", "new password too short", "warning")
                return redirect(url_for('dashboard'))
            cfg['auth_password_hash'] = generate_password_hash(new_password)
        if new_username:
            cfg['auth_username'] = new_username

    cfg['auth_2fa_enabled'] = request.form.get('auth_2fa_enabled') == 'on'
    cfg['auth_telegram_bot_token'] = str(request.form.get('auth_telegram_bot_token', '')).strip()
    cfg['auth_telegram_admin_id'] = str(request.form.get('auth_telegram_admin_id', '')).strip()
    try:
        ttl = int(request.form.get('auth_otp_ttl_seconds', cfg.get('auth_otp_ttl_seconds', 300)) or 300)
    except Exception:
        ttl = int(cfg.get('auth_otp_ttl_seconds', 300) or 300)
    cfg['auth_otp_ttl_seconds'] = max(60, min(1800, ttl))

    save_config(cfg)
    log_activity(
        "Save Auth Security Settings",
        f"user={cfg.get('auth_username','admin')} 2fa={cfg.get('auth_2fa_enabled', True)}",
        "info"
    )
    return redirect(url_for('dashboard'))

@app.route('/send_backup_now', methods=['POST'])
def send_backup_now():
    cfg = load_config()
    token = str(cfg.get('backup_bot_token', '')).strip()
    admin_id = str(cfg.get('backup_bot_admin_id', '')).strip()
    if not token or not admin_id:
        log_activity("Backup Bot Manual Send Failed", "missing token/admin id", "error")
        return redirect(url_for('dashboard'))

    backup_ref, backup_path, user_count = create_full_backup_file("manual_telegram")
    ok, msg = send_backup_to_telegram(
        token,
        admin_id,
        backup_path,
        caption=f"PanelMaster Manual Backup\nFile: {backup_ref}\nUsers: {user_count}"
    )
    if ok:
        cfg['backup_bot_last_sent_ts'] = time.time()
        save_config(cfg)
        log_activity("Backup Bot Manual Send", f"sent file={backup_ref}", "success")
    else:
        log_activity("Backup Bot Manual Send Failed", msg[:180], "error")
    return redirect(url_for('dashboard'))

@app.route('/restore_full_backup/<path:backup_ref>', methods=['POST'])
def restore_full_backup(backup_ref):
    path = safe_backup_path(BACKUP_DIR, backup_ref)
    if not path or not os.path.exists(path):
        return redirect(request.referrer or url_for('dashboard'))

    try:
        payload = read_backup_json(path)
    except Exception:
        return redirect(request.referrer or url_for('dashboard'))

    if not isinstance(payload, dict) or payload.get("type") != "full_backup":
        return redirect(request.referrer or url_for('dashboard'))

    data = payload.get("data", {}) or {}
    users_db = data.get("users_db", {})
    nodes_db = data.get("nodes_db", {})
    auto_groups = data.get("auto_groups", {})
    cfg = data.get("config", {})
    nodes_list_raw = data.get("nodes_list", "")

    if not isinstance(users_db, dict):
        return redirect(request.referrer or url_for('dashboard'))

    with db_lock:
        with open(USERS_DB, 'w') as f:
            json.dump(users_db, f, indent=4)
        if isinstance(nodes_db, dict):
            with open(NODES_DB, 'w') as f:
                json.dump(nodes_db, f, indent=4)

    if isinstance(auto_groups, dict):
        save_auto_groups(auto_groups)
    if isinstance(cfg, dict):
        save_config(cfg)
    if isinstance(nodes_list_raw, str):
        with open(NODES_LIST, 'w') as f:
            f.write(nodes_list_raw)

    with db_lock:
        with open(USERS_DB, 'r') as f:
            rebuilt_db = json.load(f)
        cmds_by_ip = build_keys_and_sync_cmds(rebuilt_db)
        with open(USERS_DB, 'w') as f:
            json.dump(rebuilt_db, f, indent=4)

    for ip, cmds in cmds_by_ip.items():
        prefix = "systemctl() { true; }; export -f systemctl; "
        suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
        execute_ssh_bg(ip, [prefix + " ; ".join(cmds) + suffix])

    log_activity("Restore Full Backup", f"file={backup_ref} users={len(users_db)}", "success")
    return redirect(url_for('dashboard'))

@app.route('/upload_backup', methods=['POST'])
def upload_backup():
    file = request.files.get('backup_file')
    if not file: return redirect(url_for('dashboard'))
    
    try:
        uploaded_data = json.load(file)

        # Full backup upload support
        if isinstance(uploaded_data, dict) and uploaded_data.get("type") == "full_backup":
            data = uploaded_data.get("data", {}) or {}
            users_db = data.get("users_db", {})
            nodes_db = data.get("nodes_db", {})
            auto_groups = data.get("auto_groups", {})
            cfg = data.get("config", {})
            nodes_list_raw = data.get("nodes_list", "")

            if not isinstance(users_db, dict):
                return redirect(url_for('dashboard'))

            with db_lock:
                with open(USERS_DB, 'w') as f:
                    json.dump(users_db, f, indent=4)
                if isinstance(nodes_db, dict):
                    with open(NODES_DB, 'w') as f:
                        json.dump(nodes_db, f, indent=4)

            if isinstance(auto_groups, dict):
                save_auto_groups(auto_groups)
            if isinstance(cfg, dict):
                save_config(cfg)
            if isinstance(nodes_list_raw, str):
                with open(NODES_LIST, 'w') as f:
                    f.write(nodes_list_raw)

            with db_lock:
                with open(USERS_DB, 'r') as f:
                    rebuilt_db = json.load(f)
                cmds_by_ip = build_keys_and_sync_cmds(rebuilt_db)
                with open(USERS_DB, 'w') as f:
                    json.dump(rebuilt_db, f, indent=4)

            for ip, cmds in cmds_by_ip.items():
                prefix = "systemctl() { true; }; export -f systemctl; "
                suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
                execute_ssh_bg(ip, [prefix + " ; ".join(cmds) + suffix])

            log_activity("Restore Full Backup Upload", f"users={len(users_db)}", "success")
            return redirect(url_for('dashboard'))
        
        with db_lock:
            db = {}
            if os.path.exists(USERS_DB):
                try:
                    with open(USERS_DB, 'r') as f: db = json.load(f)
                except: pass
            
            for uname, uinfo in uploaded_data.items():
                db[uname] = uinfo
            
            cmds_by_ip = build_keys_and_sync_cmds(db)
            
            with open(USERS_DB, 'w') as f:
                json.dump(db, f, indent=4)
                
        for ip, cmds in cmds_by_ip.items():
            prefix = "systemctl() { true; }; export -f systemctl; "
            suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
            execute_ssh_bg(ip, [prefix + " ; ".join(cmds) + suffix])
        log_activity("Restore Backup", f"users={len(uploaded_data)}", "success")
            
    except Exception as e:
        print(f"Restore Error: {e}")
        log_activity("Restore Backup Failed", str(e)[:140], "error")
        
    return redirect(url_for('dashboard'))

@app.route('/save_settings_basic', methods=['POST'])
def save_settings_basic():
    config = load_config()
    try: config['interval'] = int(request.form.get('interval', 12))
    except: config['interval'] = 12
    config['bot_token'] = request.form.get('bot_token', '')
    save_config(config)
    log_activity("Save Settings", "Updated bot token/interval", "info")
    return redirect(url_for('dashboard'))

@app.route('/config_action', methods=['POST'])
def config_action():
    config = load_config()
    ctype = request.form.get('type')
    action = request.form.get('action')
    val = request.form.get('val', '').strip()
    target_list = 'admin_ids' if ctype == 'admin' else 'mod_ids'
    
    if action == 'add' and val:
        if val not in config.get(target_list, []):
            config.setdefault(target_list, []).append(val)
    elif action == 'del' and val:
        if val in config.get(target_list, []):
            config[target_list].remove(val)
            
    save_config(config)
    log_activity("Config Action", f"type={ctype} action={action} value={val}", "info")
    return redirect(url_for('dashboard'))

@app.route('/clear_activity_logs', methods=['POST'])
def clear_activity_logs():
    try:
        with ACTIVITY_LOG_LOCK:
            with open(ACTIVITY_LOG_FILE, 'w') as f:
                json.dump([], f, indent=2)
    except Exception:
        pass
    return redirect(url_for('dashboard'))

# Background scheduler for Telegram backup delivery.
start_backup_scheduler(
    load_config,
    save_config,
    create_full_backup_file,
    log_fn=log_activity,
    poll_seconds=15
)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888)
