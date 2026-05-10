import os, threading

try:
    from config import NODES_LIST, ensure_data_dirs, safe_load_json
except ImportError:
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"
    def ensure_data_dirs():
        os.makedirs("/root/PanelMaster", exist_ok=True)
    def safe_load_json(path, default=None):
        return default if default is not None else {}

db_lock = threading.Lock()
AUTO_GROUPS_FILE = "/root/PanelMaster/auto_groups.json"
NODES_DB = "/root/PanelMaster/nodes_db.json"

def get_nodes():
    ensure_data_dirs()
    nodes = {}
    if os.path.exists(NODES_LIST):
        with open(NODES_LIST, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                if '|' in line:
                    parts = line.split('|')
                    if len(parts) >= 3:
                        nodes[parts[0].strip()] = {"name": parts[1].strip(), "ip": parts[2].strip()}
                else:
                    parts = line.rsplit(' ', 1)
                    if len(parts) == 2:
                        nodes[parts[0].strip()] = {"name": parts[0].strip(), "ip": parts[1].strip()}
    return nodes

def get_all_servers():
    import json
    ensure_data_dirs()
    servers = get_nodes()
    if os.path.exists(AUTO_GROUPS_FILE):
        groups = safe_load_json(AUTO_GROUPS_FILE, {})
        if isinstance(groups, dict):
            for gid, gdata in groups.items():
                if not isinstance(gdata, dict):
                    continue
                for nid, ndata in gdata.get("nodes", {}).items():
                    nip = str(ndata.get("ip")).strip() if isinstance(ndata, dict) else str(ndata).strip()
                    nname = ""
                    if isinstance(ndata, dict):
                        nname = str(ndata.get("name", "")).strip()
                    servers[str(nid).strip()] = {"name": nname or f"[AUTO] {nid}", "ip": nip}
    return servers

def check_live_status(db):
    active = set()
    for uname, info in db.items():
        try:
            if info.get('is_online', False) and not info.get('is_blocked', False):
                active.add(uname)
        except: pass
    return active

def check_live_status_for_node(db, node_ip):
    """Return set of DB keys that are actively transferring data on a specific node IP."""
    active = set()
    if not node_ip:
        return active
    nip = str(node_ip).strip()
    for uname, info in db.items():
        try:
            if info.get('is_blocked', False):
                continue
            online_ips = info.get('online_on_ips', [])
            if isinstance(online_ips, list) and nip in online_ips:
                active.add(uname)
        except:
            pass
    return active


COMPOSITE_SEP = "::"

def make_db_key(group_id, username):
    """Build composite DB key for auto-group users: 'group_id::username'."""
    if group_id:
        return f"{group_id}{COMPOSITE_SEP}{username}"
    return username

def get_display_name(db_key, uinfo=None):
    """Extract display username from a DB key (backward compatible)."""
    if uinfo and isinstance(uinfo, dict) and uinfo.get("username"):
        return str(uinfo["username"])
    if COMPOSITE_SEP in str(db_key):
        return str(db_key).split(COMPOSITE_SEP, 1)[1]
    return str(db_key)

def find_db_key(db, username, group_id=None):
    """Find the actual DB key for a given display username + optional group."""
    if not username:
        return None
    u = str(username).strip()
    if group_id:
        composite = make_db_key(group_id, u)
        if composite in db:
            return composite
    if u in db:
        return u
    for k, v in db.items():
        if not isinstance(v, dict):
            continue
        display = get_display_name(k, v)
        if display == u:
            if group_id and v.get("group") == group_id:
                return k
            if not group_id:
                return k
    return None

def find_all_db_keys(db, username):
    """Find ALL DB keys matching a display username (across groups)."""
    u = str(username).strip()
    keys = []
    for k, v in db.items():
        if not isinstance(v, dict):
            continue
        if get_display_name(k, v) == u:
            keys.append(k)
    return keys
