import subprocess
import threading
import base64
import shlex

_NODE_LOCKS = {}
_NODE_LOCKS_GUARD = threading.Lock()

def _get_node_lock(ip):
    key = str(ip or "").strip()
    with _NODE_LOCKS_GUARD:
        if key not in _NODE_LOCKS:
            _NODE_LOCKS[key] = threading.Lock()
        return _NODE_LOCKS[key]

def _ssh_task(ip, script_content):
    try:
        b64 = base64.b64encode(script_content.encode('utf-8')).decode('utf-8')
        full_cmd = f"ssh -o ConnectTimeout=20 -o StrictHostKeyChecking=no root@{ip} \"echo {b64} | base64 -d > /tmp/pm_task.sh && bash /tmp/pm_task.sh\""
        with _get_node_lock(ip):
            subprocess.run(full_cmd, shell=True)
    except Exception:
        pass

def execute_ssh_bg(ip, cmds):
    if not cmds: return
    if isinstance(cmds, list):
        script_content = "\n".join(cmds)
    else:
        script_content = cmds
    threading.Thread(target=_ssh_task, args=(ip, script_content), daemon=True).start()

def _clean_xray_out_tag_cmd(tag):
    """
    Remove only the exact Shadowsocks inbound tag from Xray config.

    Important safety rules:
    - Do NOT remove by port. Ports can collide across nodes/users in PanelMaster data;
      deleting by port can remove unrelated working keys.
    - Pass the tag through an environment variable so usernames containing quotes or
      shell-special characters (e.g. Mother'sHouse) cannot break the inline Python.
    """
    code = (
        "import json, os; "
        "p='/usr/local/etc/xray/config.json'; "
        "t=os.environ.get('PM_XRAY_TAG',''); "
        "d=json.load(open(p)); "
        "d['inbounds']=[i for i in d.get('inbounds',[]) if str(i.get('tag','')) != t]; "
        "json.dump(d,open(p,'w'),indent=4)"
    )
    return f"PM_XRAY_TAG={shlex.quote(str(tag))} python3 -c {shlex.quote(code)}"

# 🚀 နာမည်မပြောင်းဘဲ Protocol ပေါ်မူတည်၍ VLESS နှင့် SS အား သီးခြား အလုပ်လုပ်စေမည်
def get_safe_delete_cmd(username, protocol, port):
    username_q = shlex.quote(str(username))
    port_q = shlex.quote(str(port))
    if protocol == 'v2':
        return f"yes | /usr/local/bin/v2ray-node-del-vless {username_q} >/dev/null 2>&1 || true"
    else:
        # 🚀 Outline SS: remove only this user's exact tag (never by port).
        tag = f"out-{username}"
        py_clean = _clean_xray_out_tag_cmd(tag)
        return f"{py_clean} ; yes | /usr/local/bin/v2ray-node-del-out {username_q} {port_q} >/dev/null 2>&1 || true ; ufw delete allow {port_q}/tcp >/dev/null 2>&1 || true ; ufw delete allow {port_q}/udp >/dev/null 2>&1 || true"

def get_safe_add_out_cmd(username, uid, port):
    """
    Add SS outbound safely by cleaning stale out-* entries first:
    - remove any out-* inbound with same tag
    - never remove by port; same-port users on other nodes must not be touched
    """
    username_q = shlex.quote(str(username))
    uid_q = shlex.quote(str(uid))
    port_q = shlex.quote(str(port))
    tag = f"out-{username}"
    py_clean = _clean_xray_out_tag_cmd(tag)
    return (
        f"{py_clean} ; "
        f"/usr/local/bin/v2ray-node-add-out {username_q} {uid_q} {port_q} ; "
        f"ufw allow {port_q}/tcp >/dev/null 2>&1 || true ; "
        f"ufw allow {port_q}/udp >/dev/null 2>&1 || true"
    )
