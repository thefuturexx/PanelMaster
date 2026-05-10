import subprocess
import urllib.request
import json
import re
import os
from datetime import datetime
from utils import db_lock

IPS_DB = "/root/PanelMaster/ips_db.json"
IP_CACHE = {}

def fetch_geoip(ip):
    """IP မှ နိုင်ငံနှင့် မြို့ကို ရှာဖွေပေးမည့် API"""
    if ip in IP_CACHE: return IP_CACHE[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=4) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                city = data.get('city', '')
                country = data.get('country', '')
                isp = data.get('isp', '')
                loc = f"{city}, {country}" if city else country
                loc_str = f"{loc} ({isp})"
                IP_CACHE[ip] = loc_str
                return loc_str
            else:
                return "Rate Limit/Unknown"
    except:
        pass
    return "Unknown Location"

def get_active_ips(node_ip, port, protocol, username):
    """Network Command နှင့် Xray Log နှစ်မျိုးလုံးမှ IP များကို အမိအရ ဆွဲထုတ်မည်"""
    active_ips = set()
    
    try:
        # 🚀 ၁။ Shadowsocks အတွက် Live Connection များကို တိုက်ရိုက်ဖမ်းမည်
        if protocol == 'out': 
            # ss command ဖြင့် လက်ရှိချိတ်ဆက်နေသော IP ကို တိကျစွာ ဆွဲထုတ်ခြင်း
            cmd_live = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"ss -tn state established | grep ':{port} ' | awk '{{print \\$5}}' | cut -d: -f1\""
            res_live = subprocess.run(cmd_live, shell=True, capture_output=True, text=True, timeout=8)
            for ip in res_live.stdout.splitlines():
                ip = ip.strip()
                if ip and ip != "127.0.0.1" and ip != "0.0.0.0" and ip != node_ip:
                    active_ips.add(ip)

        # 🚀 ၂။ History အတွက် Xray Access Log မှ ပြန်လည်ရှာဖွေမည် (VLESS ကော SS ပါရမည်)
        # Shadowsocks ဆိုလျှင် ၎င်း၏ Port ဖြင့်ရှာမည်၊ VLESS ဆိုလျှင် Username ဖြင့်ရှာမည်
        search_pattern = f"{username}|:{port}" if protocol == 'out' else username
        
        cmd_log = f"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@{node_ip} \"cat /var/log/xray/access.log 2>/dev/null | grep 'accepted' | grep -E '{search_pattern}' | tail -n 1000 || journalctl -u xray --no-pager 2>/dev/null | grep 'accepted' | grep -E '{search_pattern}' | tail -n 1000\""
        res_log = subprocess.run(cmd_log, shell=True, capture_output=True, text=True, timeout=12)
        
        # Regex ဖြင့် IP ကိုတိကျစွာ ဖြတ်ထုတ်ခြင်း
        for line in res_log.stdout.splitlines():
            match = re.search(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):\d+\s+accepted', line)
            if match:
                active_ips.add(match.group(1))

    except Exception as e:
        print(f"IP Tracker Error: {e}")
        pass
        
    # Local IP များနှင့် Private IP များကို ဖယ်ရှားသန့်စင်မည်
    clean_ips = set()
    for ip in active_ips:
        if ip and not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("172.") and ip != "127.0.0.1":
            clean_ips.add(ip)
            
    # 🚀 ၃။ History DB တွင် အချိန်နှင့်တကွ မှတ်တမ်းတင်ခြင်း
    now_str = datetime.now().strftime("%Y-%m-%d %I:%M %p")
    sorted_history = []
    
    with db_lock:
        ips_db = {}
        if os.path.exists(IPS_DB):
            try:
                with open(IPS_DB, 'r') as f: ips_db = json.load(f)
            except: pass
            
        user_history = ips_db.get(username, [])
        history_dict = {entry['ip']: entry for entry in user_history}
        
        db_changed = False
        for ip in clean_ips:
            if ip not in history_dict:
                loc = fetch_geoip(ip)
                history_dict[ip] = {"ip": ip, "location": loc, "last_seen": now_str}
                db_changed = True
            else:
                history_dict[ip]["last_seen"] = now_str
                # Location မရခဲ့လျှင် ပြန်ရှာပေးမည်
                if history_dict[ip]["location"] in ["Unknown Location", "Rate Limit/Unknown", ""]:
                    history_dict[ip]["location"] = fetch_geoip(ip)
                db_changed = True
                
        # နောက်ဆုံးဝင်ထားသော IP ၁၅ ခုကို အချိန်အလိုက်စီပြီး သိမ်းမည်
        sorted_history = sorted(history_dict.values(), key=lambda x: x.get('last_seen', ''), reverse=True)[:15] 
        
        if db_changed or (len(user_history) != len(sorted_history)):
            ips_db[username] = sorted_history
            with open(IPS_DB, 'w') as f: json.dump(ips_db, f)
            
    return sorted_history
