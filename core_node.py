import json, os, uuid, base64, urllib.parse, random, string, threading, requests, re, shlex
from datetime import datetime, timedelta
from utils import db_lock, get_all_servers, make_db_key, get_display_name, find_db_key
from core_auto import find_available_node, load_auto_groups, save_auto_groups
from core_engine import execute_ssh_bg, get_safe_delete_cmd_for_variants, get_safe_add_out_cmd

try:
    from config import USERS_DB, NODES_LIST, MASTER_API_KEY, safe_load_json, safe_save_json, ensure_data_dirs
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"
    MASTER_API_KEY = "My_Super_Secret_VPN_Key_2026"
    def ensure_data_dirs(): os.makedirs("/root/PanelMaster", exist_ok=True)
    def safe_load_json(path, default=None):
        try:
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                return default if default is not None else {}
            with open(path, 'r') as f: return json.load(f)
        except Exception:
            return default if default is not None else {}
    def safe_save_json(path, data, indent=4):
        parent = os.path.dirname(path)
        if parent: os.makedirs(parent, exist_ok=True)
        with open(path, 'w') as f: json.dump(data, f, indent=indent)

def get_robust_ip(node_id):
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
                if not line:
                    continue
                normalized = line.replace('|', ' ').split()
                if not normalized:
                    continue
                nid = str(normalized[0]).strip().lower()
                if nid == node_key_l and len(normalized) >= 2:
                    return normalized[-1]
    return None

def sanitize_usernames(raw_list):
    """Return shell-safe usernames for node scripts.

    Spaces become underscores; all other unsafe chars are removed to prevent
    broken SSH commands and command injection.
    """
    cleaned = []
    for u in raw_list:
        name = str(u or "").strip().replace(" ", "_").replace("\r", "").replace("\n", "")
        name = re.sub(r"[^A-Za-z0-9_.-]", "", name)
        if name:
            cleaned.append(name[:64])
    return cleaned

def get_group_node_ips(group_id):
    groups = load_auto_groups()
    ips = []
    for nid in groups.get(group_id, {}).get("nodes", {}):
        ip = get_robust_ip(nid)
        if ip:
            ips.append(str(ip).strip())
    return ips

def generate_token():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(32))

# 🚀 Sub-Panel သို့ User Data ပို့မည့် Function (JSON Object ပြင်ဆင်ချက်)
def sync_new_user_to_subpanel(username, group_id, total_gb, expire_date, token, uid, port, proto):
    groups = load_auto_groups()
    gdata = groups.get(group_id, {})
    group_name = gdata.get("name", group_id)
    g_nodes = gdata.get("nodes", {})

    keys_dict = {}
    safe_u = urllib.parse.quote(username)
    
    for nid in g_nodes:
        nip = get_robust_ip(nid)
        if not nip: continue
        
        if proto == 'v2':
            keys_dict[nid] = f"vless://{uid}@{nip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
        else:
            # 🚀 Shadowsocks အတွက် JSON Object အတိုင်း ပို့ပေးမည်
            keys_dict[nid] = {
                "server": str(nip),
                "server_port": int(port),
                "password": str(uid),
                "method": "chacha20-ietf-poly1305",
                "prefix": "\u0016\u0003\u0001\u0005\u00f2\u0001\u0000\u0005\u00ee\u0003\u0003"
            }

    payload = {
        "name": username,
        "groupName": group_name,
        "totalGB": float(total_gb),
        "expireDate": expire_date,
        "keys": keys_dict
    }

    try:
        requests.post(
            "http://167.172.91.222:4000/api/internal/sync-user-api",
            json=payload,
            headers={"Content-Type": "application/json", "x-api-key": MASTER_API_KEY},
            timeout=10
        )
    except Exception as e:
        print(f"Sync Error: {e}")

def add_keys(node_id, group_id, raw_usernames, gb, days, proto, is_auto=False):
    ensure_data_dirs()
    usernames = sanitize_usernames(raw_usernames)
    if not usernames: return False, "❌ No usernames!"

    db = {}
    with db_lock:
        db = safe_load_json(USERS_DB, {})
        if not isinstance(db, dict): db = {}

        existing_ids = [int(u.get('key_id', 0)) for u in db.values() if isinstance(u, dict) and str(u.get('key_id', '')).isdigit()]
        next_id = max(existing_ids) + 1 if existing_ids else 1
        exp = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")

        vless_cmds = {}
        ss_cmds = {}
        max_p_global = 10000
        for uinfo in db.values():
            if isinstance(uinfo, dict) and uinfo.get('protocol') == 'out':
                try: p = int(uinfo.get('port', 10000))
                except: p = 10000
                if p > max_p_global: max_p_global = p

        for u in usernames:
            db_key = make_db_key(group_id, u) if is_auto and group_id else u
            if db_key in db:
                continue
            if not group_id and u in db:
                continue

            if is_auto:
                target_node, target_ip = find_available_node(group_id, 1, current_db=db)
                if not target_node: return False, "❌ Error: Limit Reached! No space available."
            else:
                target_node = node_id
                target_ip = get_robust_ip(node_id)
                if not target_ip: return False, "❌ Error: Node offline!"

            target_ip = str(target_ip).strip()
            uid = str(uuid.uuid4()).strip()
            safe_u = urllib.parse.quote(u)
            token = generate_token()

            if proto == 'v2':
                port = "443"
                k = f"vless://{uid}@{target_ip}:8080?path=%2Fvless&security=none&encryption=none&type=ws#{safe_u}"
                cmd = f"/usr/local/bin/v2ray-node-add-vless {shlex.quote(u)} {shlex.quote(uid)}"
                vless_cmds.setdefault(target_ip, []).append(cmd)
            else:
                max_p_global += 1
                port = str(max_p_global)
                credentials = f"chacha20-ietf-poly1305:{uid}"
                b64_creds = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8').rstrip('=')
                k = f"ss://{b64_creds}@{target_ip}:{port}#{safe_u}"
                cmd = get_safe_add_out_cmd(u, uid, port)

                target_ips = [target_ip]
                if group_id:
                    target_ips = get_group_node_ips(group_id) or [target_ip]
                for ip in target_ips:
                    ss_cmds.setdefault(str(ip).strip(), []).append(cmd)

            db[db_key] = {
                "username": u,
                "node": target_node, "group": group_id, "protocol": proto, "uuid": uid,
                "port": port, "total_gb": float(gb), "expire_date": exp,
                "used_bytes": 0, "last_raw_bytes": 0, "is_blocked": False, "is_online": False,
                "key": k, "key_id": next_id, "token": token
            }
            next_id += 1

            if is_auto and group_id:
                threading.Thread(target=sync_new_user_to_subpanel, args=(u, group_id, gb, exp, token, uid, port, proto), daemon=True).start()

        safe_save_json(USERS_DB, db, indent=4)
        
        for ip, cmds in vless_cmds.items():
            cmds.append("systemctl restart xray")
            execute_ssh_bg(ip, cmds)
            
        for ip, cmds in ss_cmds.items():
            prefix = "systemctl() { true; }; export -f systemctl; "
            suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
            combined_cmd = prefix + " ; ".join(cmds) + suffix
            execute_ssh_bg(ip, [combined_cmd])
            
        return True, "Success"

def toggle_key(db_key):
    ensure_data_dirs()
    with db_lock:
        if os.path.exists(USERS_DB):
            db = safe_load_json(USERS_DB, {})
            if not isinstance(db, dict): db = {}
            if db_key in db:
                user = db[db_key]; user['is_blocked'] = not user.get('is_blocked', False)
                display = get_display_name(db_key, user)
                ip = get_robust_ip(user.get('node'))
                if ip:
                    protocol = user.get('protocol', 'v2')
                    group_id = user.get('group')
                    target_ips = [str(ip).strip()]
                    if protocol == 'out' and group_id:
                        target_ips = get_group_node_ips(group_id) or target_ips
                    if user['is_blocked']:
                        user['is_online'] = False
                        cmd = get_safe_delete_cmd_for_variants(display, protocol, user.get('port', '443'), group_id)
                    else:
                        uid = user['uuid']
                        cmd = f"/usr/local/bin/v2ray-node-add-vless {shlex.quote(display)} {shlex.quote(uid)}" if protocol == 'v2' else get_safe_add_out_cmd(display, uid, user['port'])

                    if protocol == 'v2':
                        execute_ssh_bg(str(ip).strip(), [f"{cmd} ; systemctl restart xray"])
                    else:
                        prefix = "systemctl() { true; }; export -f systemctl; "
                        suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
                        for tip in target_ips:
                            execute_ssh_bg(str(tip).strip(), [prefix + cmd + suffix])
                safe_save_json(USERS_DB, db, indent=4)

def edit_key(db_key, total_gb, expire_date):
    ensure_data_dirs()
    with db_lock:
        if os.path.exists(USERS_DB):
            db = safe_load_json(USERS_DB, {})
            if not isinstance(db, dict): db = {}
            if db_key in db:
                if total_gb is not None: db[db_key]['total_gb'] = float(total_gb)
                if expire_date: db[db_key]['expire_date'] = expire_date
                safe_save_json(USERS_DB, db, indent=4)

def renew_key(db_key, add_gb, add_days):
    ensure_data_dirs()
    with db_lock:
        if os.path.exists(USERS_DB):
            db = safe_load_json(USERS_DB, {})
            if not isinstance(db, dict): db = {}
            if db_key in db:
                entry = db[db_key]
                display = get_display_name(db_key, entry)
                entry['total_gb'] = float(add_gb); entry['days'] = int(add_days)
                entry['expire_date'] = (datetime.now() + timedelta(days=int(add_days))).strftime("%Y-%m-%d")
                entry['used_bytes'] = 0; entry['last_raw_bytes'] = 0; entry['is_blocked'] = False; entry['is_online'] = False

                ip = get_robust_ip(entry.get('node'))
                group_id = entry.get('group')
                if ip:
                    uid = entry['uuid']
                    protocol = entry['protocol']
                    port = entry['port']
                    if protocol == 'v2':
                        cmd = f"/usr/local/bin/v2ray-node-add-vless {shlex.quote(display)} {shlex.quote(uid)}"
                        execute_ssh_bg(str(ip).strip(), [f"{cmd} ; systemctl restart xray"])
                    else:
                        cmd = get_safe_add_out_cmd(display, uid, port)
                        prefix = "systemctl() { true; }; export -f systemctl; "
                        suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
                        target_ips = [str(ip).strip()]
                        if group_id:
                            target_ips = get_group_node_ips(group_id) or target_ips
                        for tip in target_ips:
                            execute_ssh_bg(str(tip).strip(), [prefix + cmd + suffix])

                safe_save_json(USERS_DB, db, indent=4)

def delete_key(db_key):
    ensure_data_dirs()
    with db_lock:
        if os.path.exists(USERS_DB):
            db = safe_load_json(USERS_DB, {})
            if not isinstance(db, dict): db = {}
            if db_key in db:
                info = db[db_key]
                display = get_display_name(db_key, info)
                ip = get_robust_ip(info.get('node'))
                protocol = info.get('protocol', 'v2')
                if ip:
                    cmd = get_safe_delete_cmd_for_variants(display, protocol, info.get('port', '443'), info.get('group'))
                    if protocol == 'v2':
                        execute_ssh_bg(str(ip).strip(), [f"{cmd} ; systemctl restart xray"])
                    else:
                        prefix = "systemctl() { true; }; export -f systemctl; "
                        suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
                        # Delete only from the user's assigned node. Fan-out to
                        # the whole group is unsafe for SS because port numbers
                        # can collide and delete unrelated keys on sibling nodes.
                        execute_ssh_bg(str(ip).strip(), [prefix + cmd + suffix])
                del db[db_key]
                safe_save_json(USERS_DB, db, indent=4)

def bulk_delete_keys(db_keys):
    ensure_data_dirs()
    with db_lock:
        if os.path.exists(USERS_DB):
            db = safe_load_json(USERS_DB, {})
            if not isinstance(db, dict): db = {}
            vless_dels = {}
            ss_dels = {}
            for dk in db_keys:
                if dk in db:
                    info = db[dk]
                    display = get_display_name(dk, info)
                    ip = get_robust_ip(info.get('node'))
                    protocol = info.get('protocol', 'v2')
                    if ip:
                        ip = str(ip).strip()
                        cmd = get_safe_delete_cmd_for_variants(display, protocol, info.get('port', '443'), info.get('group'))
                        if protocol == 'v2':
                            vless_dels.setdefault(ip, []).append(cmd)
                        else:
                            ss_dels.setdefault(ip, []).append(cmd)
                    del db[dk]
            safe_save_json(USERS_DB, db, indent=4)
            
            for ip, cmds in vless_dels.items():
                cmds.append("systemctl restart xray")
                execute_ssh_bg(ip, cmds)
                
            for ip, cmds in ss_dels.items():
                prefix = "systemctl() { true; }; export -f systemctl; "
                suffix = " ; unset -f systemctl; systemctl reset-failed xray; systemctl restart xray"
                combined_cmd = prefix + " ; ".join(cmds) + suffix
                execute_ssh_bg(ip, [combined_cmd])

def rebalance_auto_node(group_id, new_limit, specific_node=None):
    return True, "Success"
