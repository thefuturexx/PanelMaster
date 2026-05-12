from flask import Blueprint, request, jsonify
import json, os, urllib.parse, base64, uuid, random, string, subprocess, threading, time, shlex
from datetime import datetime, timedelta

from utils import get_all_servers, db_lock, make_db_key, get_display_name, find_db_key
from core_auto import load_auto_groups
from core_engine import get_safe_delete_cmd_for_variants, get_safe_add_out_cmd

try:
    from config import USERS_DB, NODES_LIST
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"

from core_security_keys import validate_api_key_value

api_bp = Blueprint('api_bp', __name__)


def _extract_api_key():
    api_key = str(request.headers.get("x-api-key", "")).strip()
    if api_key:
        return api_key
    auth = str(request.headers.get("Authorization", "")).strip()
    if auth.lower().startswith("bearer "):
        return auth.split(None, 1)[1].strip()
    return ""


def _require_api_key():
    api_key = _extract_api_key()
    if not api_key:
        return jsonify({"success": False, "error": "API Key Missing"}), 401
    ok, meta = validate_api_key_value(api_key)
    if not ok:
        source = (meta or {}).get("source")
        code = 401 if source in ("none", "missing", "") else 403
        return jsonify({"success": False, "error": "Invalid or Revoked API Key"}), code
    return None


def resolve_group_id(groups, raw_group_id):
    """
    External panels sometimes send a cached/display group value instead of the
    exact JSON key, or include accidental whitespace. Resolve that safely to the
    canonical group id used in auto_groups.json.
    """
    candidate = str(raw_group_id or "").strip()
    if not candidate:
        return ""
    if candidate in groups:
        return candidate

    candidate_l = candidate.lower()
    for gid, gdata in groups.items():
        gid_s = str(gid).strip()
        name_s = str((gdata or {}).get("name", "")).strip()
        if candidate_l in (gid_s.lower(), name_s.lower()):
            return gid

    return candidate

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

# 🚀 အရင်က အလုပ်လုပ်ခဲ့သော ရိုးရှင်းသည့် နောက်ကွယ်မှ SSH Run သည့်စနစ် ပြန်သုံးထားသည်
def fire_ssh_bg(ip, cmd):
    if not ip: return
    safe_cmd = cmd.replace('"', '\\"')
    full_ssh = f'ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{ip} "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; {safe_cmd}"'
    subprocess.Popen(full_ssh, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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

def collect_usage_delta(ip, username, last_raw_bytes):
    if not ip:
        return 0.0, float(last_raw_bytes or 0.0)
    try:
        cmd_stats = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{ip} '/usr/local/bin/xray api statsquery --server=127.0.0.1:10085'"
        res = subprocess.run(cmd_stats, shell=True, capture_output=True, text=True, timeout=8)
        if not res.stdout:
            return 0.0, float(last_raw_bytes or 0.0)

        stats = json.loads(res.stdout).get("stat", [])
        current_val = 0.0
        for s in stats:
            p = s.get("name", "").split(">>>")
            if len(p) >= 4 and p[0] == "user" and p[1] == username:
                current_val += float(s.get("value", 0))

        last_val = float(last_raw_bytes or 0.0)
        if current_val > last_val:
            return current_val - last_val, current_val
        if current_val < last_val and current_val > 0:
            return current_val, current_val
        return 0.0, current_val
    except Exception:
        return 0.0, float(last_raw_bytes or 0.0)

def resolve_user_node_ids(groups, group_id, target_node):
    """
    Resolve all node IDs that should receive user actions (suspend/resume/delete).
    Handles bad/missing group_id by falling back to the active node and by
    discovering the real group from current node membership.
    """
    node_ids = []
    if group_id:
        node_ids = list((groups.get(group_id, {}) or {}).get("nodes", {}).keys())

    # Fallback: infer group by target node membership.
    if not node_ids and target_node:
        target_norm = str(target_node).strip().lower()
        for _, gdata in groups.items():
            g_nodes = (gdata or {}).get("nodes", {})
            for nid in g_nodes.keys():
                if str(nid).strip().lower() == target_norm:
                    node_ids = list(g_nodes.keys())
                    break
            if node_ids:
                break

    # Final fallback: at least apply on current active node.
    if not node_ids and target_node:
        node_ids = [target_node]
    return node_ids

def apply_user_action_on_nodes(username, uinfo, action):
    """
    Apply suspend/resume/delete on resolved node targets for a user record.
    """
    target_node = uinfo.get('node')
    node_ip = get_target_ip(target_node)
    active_ip = str(node_ip).strip() if node_ip else None
    port = uinfo.get('port')
    uid = uinfo.get('uuid')
    group_id = uinfo.get('group')
    proto = uinfo.get('protocol', 'out')

    groups = load_auto_groups()
    target_node_ids = resolve_user_node_ids(groups, group_id, target_node)

    # Safety: do not expand SS suspend/delete to every known node. Ports are not
    # globally unique, so a global cleanup can remove unrelated users that happen
    # to use the same port on other nodes.

    for nid in target_node_ids:
        nip = get_target_ip(nid)
        if not nip:
            continue
        nip = str(nip).strip()

        if action in ["suspend", "delete"]:
            cmd_del = get_safe_delete_cmd_for_variants(username, proto, port if proto != 'v2' else '443', group_id)
            if proto == 'v2':
                cmd_full_del = f"{cmd_del} ; systemctl restart xray"
            else:
                cmd_full_del = f"{cmd_del} ; ufw delete allow {port}/tcp >/dev/null 2>&1 || true ; ufw delete allow {port}/udp >/dev/null 2>&1 || true ; systemctl restart xray"
            if not run_ssh_sync(nip, cmd_full_del, timeout=25):
                fire_ssh_bg(nip, cmd_full_del)
        elif action == "resume":
            if proto == 'v2':
                cmd_add = f"/usr/local/bin/v2ray-node-add-vless {shlex.quote(str(username))} {shlex.quote(str(uid))} ; systemctl restart xray"
                fire_ssh_bg(nip, cmd_add)
            elif group_id or len(target_node_ids) > 1:
                cmd_add = f"{get_safe_add_out_cmd(username, uid, port)} ; systemctl restart xray"
                fire_ssh_bg(nip, cmd_add)
            elif nip == active_ip:
                cmd_add = f"{get_safe_add_out_cmd(username, uid, port)} ; systemctl restart xray"
                fire_ssh_bg(nip, cmd_add)

@api_bp.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, x-api-key, X-API-Key, Authorization'
    response.headers['Access-Control-Max-Age'] = '86400'
    return response

@api_bp.route('/conf/<token>.json', methods=['GET', 'OPTIONS'])
def api_get_ssconf(token):
    if request.method == 'OPTIONS': return jsonify({"success": True}), 200
    with db_lock:
        if not os.path.exists(USERS_DB): return jsonify({"error": "DB not found"}), 404
        with open(USERS_DB, 'r') as f: db = json.load(f)
        
    user_info = next((info for info in db.values() if isinstance(info, dict) and info.get('token') == token), None)
    if not user_info or user_info.get('is_blocked', False):
        return jsonify({"error": "Invalid token or key is blocked/expired"}), 403
        
    node_ip = get_target_ip(user_info.get('node'))
    if not node_ip: return jsonify({"error": "Target node offline"}), 500
    
    data = {
        "server": node_ip,
        "server_port": int(user_info.get('port', 10000)),
        "password": user_info.get('uuid'),
        "method": "chacha20-ietf-poly1305",
        "prefix": "\u0016\u0003\u0001\u0005\u00f2\u0001\u0000\u0005\u00ee\u0003\u0003"
    }
    return jsonify(data)

@api_bp.route('/api/active-groups', methods=['GET', 'POST', 'OPTIONS'])
def api_get_active_groups():
    if request.method == 'OPTIONS': return jsonify({"success": True}), 200
    auth_err = _require_api_key()
    if auth_err:
        return auth_err
    
    try:
        groups = load_auto_groups()
        group_list = []
        for gid, gdata in groups.items():
            nodes = (gdata or {}).get("nodes", {}) or {}
            first_node = next(iter(nodes.keys()), "") if isinstance(nodes, dict) else ""
            name = (gdata or {}).get("name", gid)
            group_list.append({
                # Current PanelMaster fields
                "id": gid,
                "name": name,
                "serverCount": len(nodes) if isinstance(nodes, dict) else 0,
                # Compatibility fields expected by external panels
                "groupId": gid,
                "groupName": name,
                "masterNodeId": first_node,
            })
        return jsonify({"success": True, "groups": group_list})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500



@api_bp.route('/metrics/transfer', methods=['GET', 'OPTIONS'])
def api_metrics_transfer():
    if request.method == 'OPTIONS': return jsonify({"success": True}), 200
    auth_err = _require_api_key()
    if auth_err:
        return auth_err

    try:
        with db_lock:
            if os.path.exists(USERS_DB):
                with open(USERS_DB, 'r') as f:
                    db = json.load(f)
            else:
                db = {}
        by_user_id = {}
        by_username = {}
        for db_key, uinfo in (db or {}).items():
            if not isinstance(uinfo, dict):
                continue
            display = get_display_name(db_key, uinfo)
            user_id = str(uinfo.get("userId") or uinfo.get("key_id") or display).strip()
            used = int(float(uinfo.get("used_bytes", 0) or 0))
            if user_id:
                by_user_id[user_id] = used
            if display:
                by_username[display] = used
        return jsonify({
            "success": True,
            "bytesTransferredByUserId": by_user_id,
            "bytesTransferredByUsername": by_username,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@api_bp.route('/api/generate-keys', methods=['POST', 'OPTIONS'])
def api_generate_keys():
    if request.method == 'OPTIONS': return jsonify({"success": True}), 200
    auth_err = _require_api_key()
    if auth_err:
        return auth_err

    req_data = request.get_json(force=True, silent=True)
    if not req_data: return jsonify({"success": False, "error": "Invalid JSON"}), 400

    raw_group_id = req_data.get('masterGroupId')
    raw_username = req_data.get('userName')
    try: total_gb = float(req_data.get('totalGB', 0))
    except: total_gb = 0.0
    expire_date = req_data.get('expireDate', (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"))
    
    if not raw_group_id or not raw_username:
        return jsonify({"success": False, "error": "Missing masterGroupId or userName"}), 400

    username = str(raw_username).strip().replace(" ", "_")
    groups = load_auto_groups()
    group_id = resolve_group_id(groups, raw_group_id)
    if group_id not in groups:
        return jsonify({"success": False, "error": "Group not found", "requestedGroupId": str(raw_group_id).strip()}), 404

    from core_auto import find_available_node
    
    with db_lock:
        if os.path.exists(USERS_DB):
            try:
                with open(USERS_DB, 'r') as f: db = json.load(f)
            except: db = {}
        else:
            db = {}

        db_key = make_db_key(group_id, username)
        if db_key in db:
            return jsonify({"success": False, "error": "User already exists in this group"}), 400

        target_node, _ = find_available_node(group_id, 1, current_db=db)
        if not target_node:
            return jsonify({"success": False, "error": "Limit Reached! No space available."}), 400

        target_ip = get_target_ip(target_node)
        uid = str(uuid.uuid4()).strip()
        token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
        safe_u = urllib.parse.quote(username)

        max_p = 10000
        for uinfo in db.values():
            if isinstance(uinfo, dict) and uinfo.get('protocol') == 'out':
                try: p = int(uinfo.get('port', 10000))
                except: p = 10000
                if p > max_p: max_p = p
        port = str(max_p + 1)

        api_keys_dict = {} 
        g_nodes = groups[group_id].get("nodes", {})
        
        # Pre-provision mode: group nodes အားလုံးတွင် key တစ်ကြိမ်တည်း add လုပ်ထားမည်
        for nid in g_nodes:
            nip = get_target_ip(nid)
            if not nip: continue
            nip = str(nip).strip()
            
            api_keys_dict[nid] = {
                "server": nip,
                "server_port": int(port),
                "password": str(uid),
                "method": "chacha20-ietf-poly1305",
                "prefix": "\u0016\u0003\u0001\u0005\u00f2\u0001\u0000\u0005\u00ee\u0003\u0003"
            }
            
            cmd_add = f"{get_safe_add_out_cmd(username, uid, port)} ; systemctl restart xray"
            fire_ssh_bg(nip, cmd_add)

        b64_creds_active = base64.urlsafe_b64encode(f"chacha20-ietf-poly1305:{uid}".encode('utf-8')).decode('utf-8').rstrip('=')
        active_key = f"ss://{b64_creds_active}@{target_ip.strip()}:{port}#{safe_u}"

        existing_ids = [int(u.get('key_id', 0)) for u in db.values() if isinstance(u, dict) and str(u.get('key_id', '')).isdigit()]
        next_id = max(existing_ids) + 1 if existing_ids else 1

        db[db_key] = {
            "username": username,
            "node": target_node, "group": group_id, "protocol": "out", "uuid": uid,
            "port": port, "total_gb": total_gb, "expire_date": expire_date,
            "used_bytes": 0, "last_raw_bytes": 0, "is_blocked": False, "is_online": False,
            "key": active_key, "key_id": next_id, "token": token
        }

        with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)

    return jsonify({"success": True, "keys": api_keys_dict, "token": token})

@api_bp.route('/api/webhook/switch', methods=['POST', 'OPTIONS'])
def webhook_switch():
    if request.method == 'OPTIONS': return jsonify({"success": True}), 200
    auth_err = _require_api_key()
    if auth_err:
        return auth_err

    req_data = request.get_json(force=True, silent=True)
    if not req_data: return jsonify({"success": False, "error": "Invalid JSON"}), 400

    token = req_data.get('token')
    target_node_raw = str(req_data.get('activeServer', '')).strip()

    if not token or not target_node_raw: 
        return jsonify({"success": False, "error": "Missing token or activeServer"}), 400

    def _norm(s):
        return str(s or "").strip().lower()

    target_node = None
    raw_n = _norm(target_node_raw)
    nodes = get_all_servers()
    for nid, ndata in nodes.items():
        nid_n = _norm(nid)
        name = str(ndata.get('name', '')).strip()
        name_n = _norm(name)
        name_no_auto = name.strip()
        if name_no_auto.startswith("[AUTO]"):
            name_no_auto = name_no_auto.replace("[AUTO]", "", 1).strip()
        name_no_auto_n = _norm(name_no_auto)

        if raw_n in {nid_n, name_n, name_no_auto_n}:
            target_node = nid
            break
            
    if not target_node: return jsonify({"success": False, "error": "Target node not found"}), 404

    new_ip = get_target_ip(target_node)
    if not new_ip: return jsonify({"success": False, "error": "Target node offline"}), 500
    new_ip = str(new_ip).strip()

    with db_lock:
        if not os.path.exists(USERS_DB): return jsonify({"success": False, "error": "DB not found"}), 404
        with open(USERS_DB, 'r') as f: db = json.load(f)
        
        username = next((uname for uname, info in db.items() if isinstance(info, dict) and info.get('token') == token), None)
        if not username: return jsonify({"success": False, "error": "Invalid token"}), 404
        uinfo = db[username]
        
        old_node = uinfo.get('node')
        if old_node == target_node: return jsonify({"success": True, "message": "Already connected"})
        
        old_ip = get_target_ip(old_node)
        old_ip = str(old_ip).strip() if old_ip else None
        
        uid = uinfo.get('uuid')
        port = uinfo.get('port')
        display = get_display_name(username, uinfo)
        safe_u = urllib.parse.quote(display)
        group_id = uinfo.get('group')
        is_blocked = uinfo.get('is_blocked', False)
        proto = uinfo.get('protocol', 'out')

        delta_bytes, _ = collect_usage_delta(old_ip, display, uinfo.get('last_raw_bytes', 0))
        if delta_bytes > 0:
            uinfo['used_bytes'] = float(uinfo.get('used_bytes', 0)) + float(delta_bytes)

        # New active node အတွက် traffic counter restart
        uinfo['last_raw_bytes'] = 0
        b64_creds = base64.urlsafe_b64encode(f"chacha20-ietf-poly1305:{uid}".encode('utf-8')).decode('utf-8').rstrip('=')
        uinfo['node'] = target_node  
        if proto == 'v2':
            uinfo['key'] = f"vless://{uid}@{new_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
        else:
            uinfo['key'] = f"ss://{b64_creds}@{new_ip}:{port}#{safe_u}"
        
        with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)
        
    # Pre-provision mode: switch တွင် DB/key server သာ ပြောင်းမည် (node sync မလုပ်တော့)
    return jsonify({"success": True, "message": "Successfully switched and synced GB"})

@api_bp.route('/api/user-action', methods=['POST', 'OPTIONS'])
def api_user_action():
    if request.method == 'OPTIONS': return jsonify({"success": True}), 200
    auth_err = _require_api_key()
    if auth_err:
        return auth_err

    req_data = request.get_json(force=True, silent=True)
    if not req_data: return jsonify({"success": False, "error": "Invalid JSON"}), 400

    token = str(req_data.get('token', '')).strip()
    raw_username = str(req_data.get('username', req_data.get('userName', req_data.get('name', '')))).strip()
    raw_group_id = str(req_data.get('group', req_data.get('masterGroupId', ''))).strip() or None
    raw_user_id = str(req_data.get('userId', req_data.get('keyId', ''))).strip()
    action_raw = str(req_data.get('action', '')).strip().lower()
    action_alias = {
        "suspend": "suspend",
        "block": "suspend",
        "blocked": "suspend",
        "pause": "suspend",
        "resume": "resume",
        "unblock": "resume",
        "unblocked": "resume",
        "unpause": "resume",
        "delete": "delete"
    }
    action = action_alias.get(action_raw)
    if not action:
        return jsonify({"success": False, "error": f"Unsupported action: {action_raw}"}), 400

    with db_lock:
        if not os.path.exists(USERS_DB):
            return jsonify({"success": False, "error": "DB not found"}), 404
        with open(USERS_DB, 'r') as f: db = json.load(f)

        db_key = None
        if token:
            db_key = next((k for k, info in db.items() if isinstance(info, dict) and info.get('token') == token), None)
        if not db_key and raw_username:
            db_key = find_db_key(db, raw_username, raw_group_id)
        if not db_key and raw_user_id:
            db_key = next((k for k, info in db.items() if isinstance(info, dict) and str(info.get('key_id', '')) == raw_user_id), None)
        if not db_key or db_key not in db:
            return jsonify({"success": False, "error": "User not found"}), 404

        uinfo = db[db_key]
        display = get_display_name(db_key, uinfo)
        target_node = uinfo.get('node')
        node_ip = get_target_ip(target_node)
        active_ip = str(node_ip).strip() if node_ip else None
        
        port = uinfo.get('port')
        uid = uinfo.get('uuid')
        group_id = uinfo.get('group')
        proto = uinfo.get('protocol', 'out')

        if action == "suspend": uinfo['is_blocked'] = True
        elif action == "resume": uinfo['is_blocked'] = False
        elif action == "delete": del db[db_key]

        with open(USERS_DB, 'w') as f: json.dump(db, f, indent=4)
        
    apply_user_action_on_nodes(display, uinfo, action)

    return jsonify({"success": True, "message": "Action completed successfully"})

@api_bp.route('/api/edit-user', methods=['POST', 'OPTIONS'])
@api_bp.route('/api/internal/edit-user', methods=['POST', 'OPTIONS'])
def api_internal_edit_user():
    if request.method == 'OPTIONS':
        return jsonify({"success": True}), 200
    auth_err = _require_api_key()
    if auth_err:
        return auth_err

    req_data = request.get_json(force=True, silent=True) or {}
    username = str(req_data.get('username', '')).strip()
    group_id = str(req_data.get('group', req_data.get('masterGroupId', ''))).strip() or None
    if not username:
        return jsonify({"success": False, "error": "Missing username"}), 400

    total_gb = req_data.get('totalGB')
    used_gb = req_data.get('usedGB')
    expire_date = str(req_data.get('expireDate', '')).strip()
    try:
        if total_gb is not None:
            total_gb = float(total_gb)
        if used_gb is not None:
            used_gb = float(used_gb)
    except Exception:
        return jsonify({"success": False, "error": "Invalid totalGB/usedGB"}), 400

    with db_lock:
        if not os.path.exists(USERS_DB):
            return jsonify({"success": False, "error": "DB not found"}), 404
        with open(USERS_DB, 'r') as f:
            db = json.load(f)
        db_key = find_db_key(db, username, group_id)
        if not db_key or not isinstance(db.get(db_key), dict):
            return jsonify({"success": False, "error": "User not found"}), 404

        uinfo = db[db_key]
        if total_gb is not None:
            uinfo['total_gb'] = total_gb
        if used_gb is not None:
            # Restore/sync path: overwrite master-side usage from client panel.
            used_bytes = max(used_gb, 0.0) * (1024 ** 3)
            uinfo['used_bytes'] = used_bytes
            uinfo['last_raw_bytes'] = 0
            if 'last_raw_bytes_map' in uinfo:
                uinfo['last_raw_bytes_map'] = {}
            uinfo['last_sync_used_bytes'] = used_bytes
            uinfo['last_usage_sync_at'] = int(time.time())
        if expire_date:
            uinfo['expire_date'] = expire_date
        # Decide block state from synced values (important for backup restore flows).
        now_date = datetime.now().strftime("%Y-%m-%d")
        total_gb_eff = float(uinfo.get('total_gb', 0) or 0)
        used_bytes_eff = float(uinfo.get('used_bytes', 0) or 0)
        limit_bytes = total_gb_eff * (1024 ** 3)
        is_over_limit = limit_bytes > 0 and used_bytes_eff >= limit_bytes
        is_expired = bool(uinfo.get('expire_date')) and now_date > str(uinfo.get('expire_date'))
        uinfo['is_blocked'] = bool(is_over_limit or is_expired)
        uinfo['is_online'] = False
        if 'block_enforced' in uinfo:
            uinfo['block_enforced'] = bool(uinfo['is_blocked']) is False

        with open(USERS_DB, 'w') as f:
            json.dump(db, f, indent=4)

    display = get_display_name(db_key, uinfo)
    if uinfo.get('is_blocked', False):
        apply_user_action_on_nodes(display, uinfo, "suspend")
    else:
        apply_user_action_on_nodes(display, uinfo, "resume")
    return jsonify({"success": True, "message": "Action completed successfully"})

@api_bp.route('/api/internal/block-user', methods=['POST', 'OPTIONS'])
def api_internal_block_user():
    if request.method == 'OPTIONS':
        return jsonify({"success": True}), 200
    auth_err = _require_api_key()
    if auth_err:
        return auth_err

    req_data = request.get_json(force=True, silent=True) or {}
    username = str(req_data.get('username', '')).strip()
    group_id = str(req_data.get('group', req_data.get('masterGroupId', ''))).strip() or None
    if not username:
        return jsonify({"success": False, "error": "Missing username"}), 400

    with db_lock:
        if not os.path.exists(USERS_DB):
            return jsonify({"success": False, "error": "DB not found"}), 404
        with open(USERS_DB, 'r') as f:
            db = json.load(f)
        db_key = find_db_key(db, username, group_id)
        if not db_key or not isinstance(db.get(db_key), dict):
            return jsonify({"success": False, "error": "User not found"}), 404

        uinfo = db[db_key]
        uinfo['is_blocked'] = True
        uinfo['is_online'] = False
        uinfo['block_enforced'] = False
        with open(USERS_DB, 'w') as f:
            json.dump(db, f, indent=4)

    display = get_display_name(db_key, uinfo)
    apply_user_action_on_nodes(display, uinfo, "suspend")
    return jsonify({"success": True, "message": "Action completed successfully"})

@api_bp.route('/api/internal/delete-user', methods=['POST', 'OPTIONS'])
def api_internal_delete_user():
    if request.method == 'OPTIONS':
        return jsonify({"success": True}), 200
    auth_err = _require_api_key()
    if auth_err:
        return auth_err

    req_data = request.get_json(force=True, silent=True) or {}
    username = str(req_data.get('username', '')).strip()
    token = str(req_data.get('token', '')).strip()
    req_group = str(req_data.get('group', req_data.get('masterGroupId', ''))).strip() or None

    with db_lock:
        if not os.path.exists(USERS_DB):
            return jsonify({"success": False, "error": "DB not found"}), 404
        with open(USERS_DB, 'r') as f:
            db = json.load(f)

        db_key = None
        if token:
            db_key = next((k for k, i in db.items() if isinstance(i, dict) and i.get('token') == token), None)
        if not db_key and username:
            db_key = find_db_key(db, username, req_group)
        if not db_key or db_key not in db:
            return jsonify({"success": False, "error": "User not found"}), 404

        uinfo = db[db_key]
        display = get_display_name(db_key, uinfo)
        group_id = uinfo.get('group')
        target_node = uinfo.get('node')
        port = uinfo.get('port')
        proto = uinfo.get('protocol', 'out')
        del db[db_key]

        with open(USERS_DB, 'w') as f:
            json.dump(db, f, indent=4)

    groups = load_auto_groups()
    target_node_ids = resolve_user_node_ids(groups, group_id, target_node)
    for nid in target_node_ids:
        nip = get_target_ip(nid)
        if not nip:
            continue
        nip = str(nip).strip()
        cmd_del = get_safe_delete_cmd_for_variants(display, proto, port if proto != 'v2' else '443', group_id)
        if proto == 'v2':
            cmd_full_del = f"{cmd_del} ; systemctl restart xray"
        else:
            cmd_full_del = f"{cmd_del} ; ufw delete allow {port}/tcp >/dev/null 2>&1 || true ; ufw delete allow {port}/udp >/dev/null 2>&1 || true ; systemctl restart xray"
        fire_ssh_bg(nip, cmd_full_del)

    return jsonify({"success": True, "message": "User deleted"})


@api_bp.route('/api/debug/sync-node-stats-preview', methods=['GET'])
def debug_sync_node_stats_preview():
    """Show exactly what payload sync-node-stats would send (same logic as UI)."""
    from core_monitor import _build_sync_url, _get_sync_api_key, get_target_ip

    groups = load_auto_groups()
    with db_lock:
        if os.path.exists(USERS_DB):
            with open(USERS_DB, 'r') as f:
                db = json.load(f)
        else:
            db = {}

    target_url = _build_sync_url("sync-node-stats") or "(no base url)"
    api_key = _get_sync_api_key()

    result = {
        "target_url": target_url,
        "api_key_preview": api_key[:12] + "..." if len(api_key) > 12 else api_key,
        "groups": {}
    }

    for gid, gdata in groups.items():
        g_nodes = gdata.get("nodes", {})
        if not g_nodes:
            continue

        node_info = {}
        node_counts = {}
        for nid in g_nodes:
            nip = str(get_target_ip(nid) or "").strip()
            node_info[nid] = {"ip": nip}
            count = 0
            if nip:
                for ui in db.values():
                    if not isinstance(ui, dict) or ui.get('is_blocked'):
                        continue
                    if ui.get('group') != gid:
                        continue
                    oips = ui.get('online_on_ips', [])
                    if isinstance(oips, list) and nip in oips:
                        count += 1
            node_counts[nid] = count

        result["groups"][gid] = {
            "payload_that_would_be_sent": {
                "masterGroupId": gid,
                "nodes": node_counts
            },
            "node_details": node_info
        }

    return jsonify(result)
