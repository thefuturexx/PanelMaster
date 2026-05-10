import json, os, subprocess, threading, time
from utils import get_all_servers, db_lock, get_safe_delete_cmd

try:
    from config import USERS_DB
except ImportError:
    USERS_DB = "/root/PanelMaster/users_db.json"

# 🚀 SSH Command များကို သေချာပေါက် Run ပေးမည့် ဗဟိုစနစ် (Crash / Hang လုံးဝမဖြစ်စေရ)
def execute_ssh(ip, commands):
    if not commands: return
    cmd_str = " ; ".join(commands)
    full_cmd = f"ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no root@{ip} \"{cmd_str}\""
    subprocess.run(full_cmd, shell=True)

# 🚀 Background တွင် Data စစ်ဆေးပြီး GB ပြည့်ပါက သေချာပေါက် ပိတ်ချမည့်စနစ်
def sync_node_traffic():
    while True:
        time.sleep(30)
        try:
            nodes = get_all_servers()
            if not nodes: continue
            
            with db_lock:
                if not os.path.exists(USERS_DB): continue
                with open(USERS_DB, 'r') as f: db = json.load(f)
            
            if not db: continue
            db_changed = False
            users_to_block = []

            for node_id, info in nodes.items():
                node_ip = info.get('ip')
                if not node_ip: continue
                
                try:
                    cmd = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"/usr/local/bin/xray api statsquery --server=127.0.0.1:10085\""
                    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    user_bytes = {}
                    
                    if res.stdout.strip():
                        stats = json.loads(res.stdout).get("stat", [])
                        for s in stats:
                            parts = s.get("name", "").split(">>>")
                            val = s.get("value", 0)
                            if len(parts) >= 4:
                                if parts[0] == "user": user_bytes[parts[1]] = user_bytes.get(parts[1], 0) + val
                                elif parts[0] == "inbound" and parts[1].startswith("out-"): user_bytes[parts[1][4:]] = user_bytes.get(parts[1][4:], 0) + val
                    
                    for uname, uinfo in db.items():
                        if uinfo.get("node") == node_id:
                            val = user_bytes.get(uname, uinfo.get('last_raw_bytes', 0))
                            last_raw = uinfo.get('last_raw_bytes', 0)
                            
                            # Online / Offline / Pending စနစ် အတိအကျတွက်ချက်ခြင်း
                            if val > last_raw: uinfo['is_online'] = True
                            else: uinfo['is_online'] = False
                                
                            if val < last_raw: uinfo['used_bytes'] = uinfo.get('used_bytes', 0) + val
                            else: uinfo['used_bytes'] = uinfo.get('used_bytes', 0) + (val - last_raw)
                            
                            uinfo['last_raw_bytes'] = val
                            db_changed = True
                            
                            # GB ပြည့်ပါက Block List သို့ ထည့်မည်
                            tot_gb = float(uinfo.get('total_gb', 0))
                            if tot_gb > 0:
                                max_bytes = tot_gb * (1024**3)
                                if float(uinfo['used_bytes']) >= max_bytes and not uinfo.get('is_blocked', False):
                                    uinfo['is_blocked'] = True
                                    uinfo['is_online'] = False
                                    users_to_block.append((node_ip, uname, uinfo.get('protocol', 'v2'), uinfo.get('port', '443')))
                except Exception: pass

            if db_changed:
                with db_lock:
                    with open(USERS_DB, 'w') as f: json.dump(db, f)

            # Block လုပ်ရမည့် Key များကို Xray ထဲမှ သေချာပေါက် ပိတ်ချမည်
            for node_ip, uname, proto, port in users_to_block:
                safe_cmd = get_safe_delete_cmd(uname, proto, port)
                execute_ssh(node_ip, [safe_cmd, "systemctl restart xray"])

        except Exception: pass

def start_core_monitor():
    threading.Thread(target=sync_node_traffic, daemon=True).start()
