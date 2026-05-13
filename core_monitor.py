import json, os, time, subprocess, threading, requests
from datetime import datetime

from utils import get_all_servers, db_lock, get_display_name
from core_auto import load_auto_groups
from core_engine import get_safe_delete_cmd_for_variants, execute_ssh_bg

try:
    from config import USERS_DB, NODES_LIST, load_config, safe_load_json, safe_save_json, ensure_data_dirs
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"
    NODES_LIST = "/root/PanelMaster/nodes_list.txt"
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

_IP_FAIL_CACHE = {}
_IP_FAIL_LOCK = threading.Lock()
_MONITOR_STATUS = {
    "thread_started": False,
    "started_at": 0,
    "last_loop_at": 0,
    "last_error": "",
    "loop_count": 0,
    "last_sync_attempt_at": 0,
    "last_sync_ok_at": 0,
    "last_sync_user": "",
    "last_sync_status": ""
}
_MONITOR_STATUS_LOCK = threading.Lock()
_MONITOR_THREAD = None
_MONITOR_THREAD_LOCK = threading.Lock()


def _set_monitor_status(**kwargs):
    with _MONITOR_STATUS_LOCK:
        _MONITOR_STATUS.update(kwargs)


def get_monitor_status():
    with _MONITOR_STATUS_LOCK:
        return dict(_MONITOR_STATUS)


def _parse_monitor_interval(raw_interval):
    try:
        val = float(raw_interval)
    except Exception:
        return 12.0
    if val < 1.0:
        return 1.0
    return val


def _normalize_sync_base(raw):
    """Turn any input (domain, full URL, etc.) into a clean base like https://dash.example.com"""
    raw = str(raw or "").strip().rstrip("/")
    if not raw:
        return ""
    for suffix in ["/api/internal/sync-user-usage", "/api/internal/sync-node-stats",
                   "/api/internal/sync-new-server", "/api/internal", "/api"]:
        if raw.lower().endswith(suffix):
            raw = raw[:-len(suffix)]
            break
    raw = raw.rstrip("/")
    if raw and not raw.startswith("http"):
        raw = "https://" + raw
    return raw


def _get_sync_base_url():
    cfg = {}
    try:
        cfg = load_config() or {}
    except Exception:
        cfg = {}
    raw = str(cfg.get("external_sync_url", "")).strip()
    if not raw:
        raw = str(os.environ.get("PANEL_SYNC_PRIMARY_URL", "")).strip()
    return _normalize_sync_base(raw)


def _build_sync_url(endpoint):
    """Build full sync URL for a given endpoint name (e.g. 'sync-user-usage')."""
    base = _get_sync_base_url()
    if not base:
        return ""
    return f"{base}/api/internal/{endpoint}"


def _get_sync_api_key():
    cfg = {}
    try:
        cfg = load_config() or {}
    except Exception:
        cfg = {}
    key = str(cfg.get("external_sync_api_key", "")).strip()
    if key:
        return key
    return str(os.environ.get("PANEL_SYNC_API_KEY", "")).strip()


def _skip_ip_temporarily(ip):
    now = time.time()
    with _IP_FAIL_LOCK:
        rec = _IP_FAIL_CACHE.get(ip, {"fails": 0, "retry_at": 0.0})
        if rec.get("retry_at", 0.0) > now:
            return True
    return False


def _mark_ip_result(ip, ok):
    now = time.time()
    with _IP_FAIL_LOCK:
        if ok:
            _IP_FAIL_CACHE.pop(ip, None)
            return
        rec = _IP_FAIL_CACHE.get(ip, {"fails": 0, "retry_at": 0.0})
        fails = int(rec.get("fails", 0)) + 1
        backoff = min(30, 10 * min(fails, 3))
        _IP_FAIL_CACHE[ip] = {"fails": fails, "retry_at": now + backoff}

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

def resolve_user_node_ids(groups, group_id, target_node):
    node_ids = []
    if group_id:
        node_ids = list((groups.get(group_id, {}) or {}).get("nodes", {}).keys())
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
    if not node_ids and target_node:
        node_ids = [target_node]
    return node_ids

def suspend_user_everywhere(username, uinfo):
    port = uinfo.get('port')
    group_id = uinfo.get('group')
    target_node = uinfo.get('node')
    proto = uinfo.get('protocol', 'out')
    groups = load_auto_groups()
    node_ids = resolve_user_node_ids(groups, group_id, target_node)
    # Safety: never fan SS deletes out to every known node. A blocked/expired
    # user can share a port number with unrelated users on other nodes; global
    # delete-by-port cleanup caused healthy keys to disappear. Only enforce on
    # the user's resolved group/current node set.

    ok_count = 0
    total_targets = 0
    for nid in node_ids:
        nip = get_target_ip(nid)
        if not nip:
            continue
        total_targets += 1
        cmd_del = get_safe_delete_cmd_for_variants(username, proto, port if proto != 'v2' else '443', group_id)
        if proto == 'v2':
            remote_cmd = f"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; {cmd_del} ; systemctl restart xray"
        else:
            remote_cmd = f"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; {cmd_del} ; ufw delete allow {port}/tcp >/dev/null 2>&1 || true ; ufw delete allow {port}/udp >/dev/null 2>&1 || true ; systemctl restart xray"
        try:
            # Use argv form (no shell quoting pitfalls) so usernames/commands stay intact.
            res = subprocess.run(
                ["ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no", f"root@{nip}", remote_cmd],
                capture_output=True,
                text=True,
                timeout=25
            )
            if res.returncode == 0:
                ok_count += 1
            else:
                execute_ssh_bg(nip, [remote_cmd])
        except Exception:
            execute_ssh_bg(nip, [remote_cmd])

    # Enforced only when deletion succeeds on every reachable target node.
    return total_targets > 0 and ok_count == total_targets

def query_ip_user_totals(ip):
    totals = {}
    if not ip:
        return totals
    if _skip_ip_temporarily(ip):
        print(f"[monitor] SKIP ip={ip} (backoff)")
        return totals
    try:
        cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@{ip} '/usr/local/bin/xray api statsquery --server=127.0.0.1:10085'"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=8)
        if res.returncode != 0 or not res.stdout:
            _mark_ip_result(ip, False)
            print(f"[monitor] FAIL ip={ip} rc={res.returncode} stdout_len={len(res.stdout or '')} stderr={( res.stderr or '')[:120]}")
            return totals

        stats = json.loads(res.stdout).get("stat", [])
        for s in stats:
            p = s.get("name", "").split(">>>")
            val = float(s.get("value", 0) or 0)
            if len(p) >= 4 and p[0] == "user":
                uname = p[1]
                totals[uname] = totals.get(uname, 0.0) + val
                if "::" in uname:
                    totals[uname.split("::", 1)[1]] = totals.get(uname.split("::", 1)[1], 0.0) + val
            elif len(p) >= 4 and p[0] == "inbound" and str(p[1]).startswith("out-"):
                uname = str(p[1])[4:]
                totals[uname] = totals.get(uname, 0.0) + val
                if "::" in uname:
                    totals[uname.split("::", 1)[1]] = totals.get(uname.split("::", 1)[1], 0.0) + val
        _mark_ip_result(ip, True)
    except Exception as ex:
        _mark_ip_result(ip, False)
        print(f"[monitor] EXCEPTION ip={ip} error={ex}")
    return totals

def sync_usage_to_subpanel(db_key, uinfo, node_active_count=0):
    try:
        username = get_display_name(db_key, uinfo)
        now_ts = int(time.time())
        _set_monitor_status(last_sync_attempt_at=now_ts, last_sync_user=str(username))
        used_bytes = float(uinfo.get('used_bytes', 0) or 0)
        total_gb = float(uinfo.get('total_gb', 0) or 0)
        used_gb = used_bytes / (1024 ** 3)
        remaining_gb = max(total_gb - used_gb, 0.0)
        online_ips = uinfo.get('online_on_ips', [])

        payload = {
            "name": username,
            "usedGB": round(used_gb, 4),
            "totalGB": total_gb,
            "remainingGB": round(remaining_gb, 4),
            "expireDate": uinfo.get('expire_date'),
            "isBlocked": bool(uinfo.get('is_blocked', False)),
            "isActive": bool(uinfo.get('is_online', False)) and not bool(uinfo.get('is_blocked', False)),
            "node": uinfo.get('node', ''),
            "group": uinfo.get('group', ''),
            "activeOnIps": online_ips if isinstance(online_ips, list) else [],
            "nodeActiveUsers": int(node_active_count)
        }

        api_key = _get_sync_api_key()
        url = _build_sync_url("sync-user-usage")
        if not url or not api_key:
            print(f"[usage-sync] SKIP user={username} reason={'no sync URL' if not url else 'no API key'} — set in Dashboard Settings")
            return

        headers = {"Content-Type": "application/json", "x-api-key": api_key}
        delivered = False
        for url in [url]:
            try:
                r = requests.post(url, json=payload, headers=headers, timeout=6)
                body_preview = (r.text or "").strip().replace("\n", " ")[:240]
                print(f"[usage-sync] user={username} url={url} status={r.status_code} body={body_preview}")
                if 200 <= r.status_code < 300:
                    delivered = True
                    _set_monitor_status(
                        last_sync_ok_at=now_ts,
                        last_sync_user=str(username),
                        last_sync_status=f"{r.status_code} {url}"
                    )
                    break
            except Exception:
                print(f"[usage-sync] user={username} url={url} error=request_failed")

        if not delivered:
            _set_monitor_status(last_sync_status="failed_all_targets", last_sync_user=str(username))
            print(f"[usage-sync] user={username} result=failed_all_targets")
    except Exception:
        _set_monitor_status(last_sync_status="exception", last_sync_user=str(username))
        print(f"[usage-sync] user={username} result=exception")


def count_db_assigned_node_keys(db, group_id, node_id):
    """Fallback count from PanelMaster DB when a node cannot be reached."""
    gid = str(group_id or "").strip()
    nid_norm = str(node_id or "").strip().lower()
    count = 0
    for _, ui in (db or {}).items():
        if not isinstance(ui, dict):
            continue
        if str(ui.get('group') or "").strip() != gid:
            continue
        if str(ui.get('node') or "").strip().lower() == nid_norm:
            count += 1
    return count


def count_actual_node_keys(node_ip):
    """Return actual key count from a node's Xray config, or None on failure.

    PanelMaster's SS provisioning creates one Shadowsocks inbound per key; older
    VLESS/VMess layouts keep users under settings.clients.  Count both shapes
    while ignoring control/API inbounds such as dokodemo-door.
    """
    ip = str(node_ip or "").strip()
    if not ip:
        return None

    remote_script = r'''
import json, os
paths = ["/usr/local/etc/xray/config.json", "/etc/xray/config.json"]
for path in paths:
    if not os.path.exists(path):
        continue
    with open(path, "r") as fh:
        data = json.load(fh)
    total = 0
    for inbound in data.get("inbounds", []) if isinstance(data, dict) else []:
        if not isinstance(inbound, dict):
            continue
        proto = str(inbound.get("protocol") or "").lower()
        tag = str(inbound.get("tag") or "").lower()
        if proto in ("dokodemo-door", "api") or tag in ("api", "dokodemo-door"):
            continue
        settings = inbound.get("settings") or {}
        clients = settings.get("clients")
        if isinstance(clients, list) and clients:
            total += len(clients)
        elif proto == "shadowsocks" and inbound.get("port"):
            total += 1
    print(total)
    raise SystemExit(0)
raise SystemExit(2)
'''
    try:
        result = subprocess.run(
            [
                "ssh",
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=6",
                f"root@{ip}",
                "python3 -c " + repr(remote_script),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return None
        for line in reversed((result.stdout or "").splitlines()):
            line = line.strip()
            if line.isdigit():
                return int(line)
    except Exception:
        return None
    return None

def sync_node_stats_to_subpanel(groups, db):
    """Push per-group node key counts to external panel.

    Prefer the actual Xray config on each node.  The panel DB can contain stale
    node ids after group/server renames, but the subpanel card needs the real
    number of keys currently provisioned on that node.
    """
    try:
        api_key = _get_sync_api_key()
        url = _build_sync_url("sync-node-stats")
        if not url or not api_key:
            return
        headers = {"Content-Type": "application/json", "x-api-key": api_key}

        for gid, gdata in groups.items():
            g_nodes = gdata.get("nodes", {})
            if not g_nodes:
                continue

            node_counts = {}
            node_ip_map = {}
            for nid in g_nodes:
                nip = str(get_target_ip(nid) or "").strip()
                node_ip_map[nid] = nip
                actual_count = count_actual_node_keys(nip) if nip else None
                if actual_count is None:
                    actual_count = count_db_assigned_node_keys(db, gid, nid)
                node_counts[nid] = actual_count

            print(f"[node-stats-sync] DEBUG group={gid} node_ips={node_ip_map} key_counts={node_counts}")

            payload = {
                "masterGroupId": gid,
                "nodes": node_counts
            }

            try:
                r = requests.post(url, json=payload, headers=headers, timeout=6)
                body = (r.text or "").strip()[:200]
                print(f"[node-stats-sync] group={gid} url={url} status={r.status_code} body={body} nodes={node_counts}")
            except Exception as ex:
                print(f"[node-stats-sync] group={gid} url={url} error={ex}")
    except Exception as e:
        print(f"[node-stats-sync] error: {e}")


def get_user_monitor_ips(uinfo, groups, monitor_skip_nodes=None):
    ips = []
    group_id = uinfo.get('group')
    target_node = uinfo.get('node')
    skip_set = set()
    if isinstance(monitor_skip_nodes, (list, tuple, set)):
        skip_set = {str(x).strip().lower() for x in monitor_skip_nodes if str(x).strip()}

    g_nodes = {}
    if group_id:
        g_nodes = (groups.get(group_id, {}) or {}).get("nodes", {})

        # Fallback for stale/incorrect group id: infer by current node membership.
        if not g_nodes and target_node:
            target_norm = str(target_node).strip().lower()
            for _, gdata in groups.items():
                nodes = (gdata or {}).get("nodes", {})
                for nid in nodes.keys():
                    if str(nid).strip().lower() == target_norm:
                        g_nodes = nodes
                        break
                if g_nodes:
                    break

    if g_nodes:
        for nid in g_nodes:
            if str(nid).strip().lower() in skip_set:
                continue
            nip = get_target_ip(nid)
            if nip:
                ips.append(str(nip).strip())
    else:
        # Final fallback: at least monitor active node to keep auto-block working.
        if str(target_node).strip().lower() in skip_set:
            target_node = ""
        nip = get_target_ip(target_node)
        if nip:
            ips.append(str(nip).strip())
    # Keep unique order
    seen = set()
    out = []
    for ip in ips:
        if ip and ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out

def monitor_traffic():
    _set_monitor_status(thread_started=True, started_at=int(time.time()))
    print("[monitor] traffic monitor thread started")
    while True:
        try:
            config = load_config()
            interval = _parse_monitor_interval(config.get('interval', 12))
            monitor_skip_nodes = config.get('monitor_skip_nodes', [])
        except:
            interval = 12.0
            monitor_skip_nodes = []

        try:
            time.sleep(interval)
        except Exception:
            time.sleep(12.0)
        try:
            _set_monitor_status(last_loop_at=int(time.time()), loop_count=int(get_monitor_status().get("loop_count", 0)) + 1)
            ensure_data_dirs()
            with db_lock:
                db = safe_load_json(USERS_DB, {})
                if not isinstance(db, dict):
                    db = {}

            if not db: continue

            groups = load_auto_groups()

            # Pre-provision mode support:
            # build monitored IP list per user (group users => all group nodes).
            user_ips_map = {}
            all_ips = set()
            for uname, uinfo in db.items():
                if not isinstance(uinfo, dict) or uinfo.get('is_blocked', False):
                    continue
                ips = get_user_monitor_ips(uinfo, groups, monitor_skip_nodes=monitor_skip_nodes)
                if ips:
                    user_ips_map[uname] = ips
                    all_ips.update(ips)

            db_changed = False
            current_date = datetime.now().strftime("%Y-%m-%d")

            # Query each IP once.
            ip_totals_map = {}
            for ip in all_ips:
                ip_totals_map[ip] = query_ip_user_totals(ip)

            # Update each user by summing diffs across monitored nodes.
            for uname, uinfo in db.items():
                if not isinstance(uinfo, dict):
                    continue

                # If user is already blocked, keep retrying node-side enforcement until success.
                # Also retry when stale active-node markers remain: older delete logic could mark
                # block_enforced=True after deleting out-aa2 while the real node tag was
                # out-Group::aa2, leaving the blocked key usable on another group node.
                if uinfo.get('is_blocked', False):
                    needs_enforcement = (
                        not bool(uinfo.get('block_enforced', False))
                        or bool(uinfo.get('is_online', False))
                        or bool(uinfo.get('online_on_ips'))
                    )
                    if needs_enforcement:
                        enforced = suspend_user_everywhere(get_display_name(uname, uinfo), uinfo)
                        if enforced:
                            uinfo['block_enforced'] = True
                            uinfo['is_online'] = False
                            uinfo['online_on_ips'] = []
                            db_changed = True
                    continue

                if uname not in user_ips_map:
                    continue

                display = get_display_name(uname, uinfo)

                last_map = uinfo.get('last_raw_bytes_map')
                if not isinstance(last_map, dict):
                    last_map = {}

                total_diff = 0.0
                current_total = 0.0
                active_ips = []

                for ip in user_ips_map[uname]:
                    current_val = float(ip_totals_map.get(ip, {}).get(display, 0.0))
                    last_val = float(last_map.get(ip, 0.0) or 0.0)

                    diff = 0.0
                    if current_val > last_val:
                        diff = current_val - last_val
                    elif current_val < last_val and current_val > 0:
                        diff = current_val

                    if diff > 0:
                        total_diff += diff
                        active_ips.append(ip)

                    last_map[ip] = current_val
                    current_total += current_val

                if total_diff > 0:
                    uinfo['used_bytes'] = float(uinfo.get('used_bytes', 0)) + total_diff
                    db_changed = True

                now_online = total_diff > 0
                if bool(uinfo.get('is_online', False)) != now_online:
                    uinfo['is_online'] = now_online
                    db_changed = True

                new_active_ips = sorted(active_ips) if active_ips else []
                old_active_ips = uinfo.get('online_on_ips', [])
                if new_active_ips:
                    if new_active_ips != old_active_ips:
                        uinfo['online_on_ips'] = new_active_ips
                        uinfo['_online_ips_seen_at'] = int(time.time())
                        db_changed = True
                else:
                    last_seen = int(uinfo.get('_online_ips_seen_at', 0) or 0)
                    if old_active_ips and (int(time.time()) - last_seen) < 60:
                        pass
                    elif old_active_ips:
                        uinfo['online_on_ips'] = []
                        db_changed = True

                if uinfo.get('last_raw_bytes_map') != last_map:
                    uinfo['last_raw_bytes_map'] = last_map
                    db_changed = True

                # Keep legacy aggregate for backward compatibility.
                if float(uinfo.get('last_raw_bytes', 0.0) or 0.0) != current_total:
                    uinfo['last_raw_bytes'] = current_total
                    db_changed = True

                if total_diff > 0:
                    now_ts = int(time.time())
                    last_sync_at = int(uinfo.get('last_usage_sync_at', 0) or 0)
                    last_sync_bytes = float(uinfo.get('last_sync_used_bytes', 0) or 0)
                    current_used = float(uinfo.get('used_bytes', 0) or 0)
                    delta_since_last_sync = max(current_used - last_sync_bytes, 0.0)
                    if (now_ts - last_sync_at) >= 30 or delta_since_last_sync >= (50 * 1024 * 1024):
                        user_node_ip = str(get_target_ip(uinfo.get('node')) or "").strip()
                        nac = 0
                        if user_node_ip:
                            for _u, _ui in db.items():
                                if not isinstance(_ui, dict) or _ui.get('is_blocked'):
                                    continue
                                _oips = _ui.get('online_on_ips', [])
                                if isinstance(_oips, list) and user_node_ip in _oips:
                                    nac += 1
                        sync_usage_to_subpanel(uname, uinfo, node_active_count=nac)
                        uinfo['last_usage_sync_at'] = now_ts
                        uinfo['last_sync_used_bytes'] = current_used
                        db_changed = True

                limit_bytes = float(uinfo.get('total_gb', 0)) * (1024**3)
                is_over_limit = limit_bytes > 0 and float(uinfo.get('used_bytes', 0)) >= limit_bytes
                is_expired = uinfo.get('expire_date') and current_date > uinfo.get('expire_date')

                if is_over_limit or is_expired:
                    uinfo['is_blocked'] = True
                    uinfo['is_online'] = False
                    uinfo['block_enforced'] = False
                    db_changed = True
                    enforced = suspend_user_everywhere(display, uinfo)
                    if enforced:
                        uinfo['block_enforced'] = True
                        db_changed = True

            if db_changed:
                with db_lock:
                    current_db = safe_load_json(USERS_DB, {})
                    if not isinstance(current_db, dict):
                        current_db = {}
                    for uname, uinfo in db.items():
                        if uname in current_db:
                            current_db[uname].update(uinfo)
                    safe_save_json(USERS_DB, current_db, indent=4)

            now_ts = int(time.time())
            last_node_sync = int(_MONITOR_STATUS.get("last_node_stats_sync_at", 0) or 0)
            if (now_ts - last_node_sync) >= 30:
                threading.Thread(target=sync_node_stats_to_subpanel, args=(groups, db), daemon=True).start()
                _MONITOR_STATUS["last_node_stats_sync_at"] = now_ts

        except Exception as e:
            _set_monitor_status(last_error=str(e)[:300])
            print(f"[monitor] loop error: {e}")

def start_background_monitor():
    global _MONITOR_THREAD
    with _MONITOR_THREAD_LOCK:
        if _MONITOR_THREAD and _MONITOR_THREAD.is_alive():
            return _MONITOR_THREAD
        t = threading.Thread(target=monitor_traffic, daemon=True)
        t.start()
        _MONITOR_THREAD = t
        return t
