import json
import os
import re
from datetime import datetime


def _safe_file_name(name):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(name or "").strip())


def _fmt_size(path):
    try:
        size_kb = os.path.getsize(path) / 1024.0
        return f"{size_kb:.1f} KB"
    except Exception:
        return "0.0 KB"


def _fmt_time(path):
    try:
        return datetime.fromtimestamp(os.path.getctime(path)).strftime("%Y-%m-%d %I:%M %p")
    except Exception:
        return "-"


def _node_id_from_name(filename):
    # New format: node_backup__<node_id>__<timestamp>.json
    if filename.startswith("node_backup__") and filename.endswith(".json"):
        body = filename[len("node_backup__"):-len(".json")]
        parts = body.split("__")
        if len(parts) >= 2:
            return parts[0]

    # Legacy format: backup_<node_id>_<timestamp>.json
    if filename.startswith("backup_") and filename.endswith(".json"):
        body = filename[len("backup_"):-len(".json")]
        # timestamp part has fixed length YYYYMMDD_HHMMSS = 15
        if len(body) > 16 and body[-16] == "_":
            return body[:-16]
        bits = body.split("_")
        if len(bits) >= 2:
            return "_".join(bits[:-2]) if len(bits) > 2 else bits[0]
    return None


def _rel(path, root):
    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except Exception:
        return os.path.basename(path)


def safe_backup_path(backup_dir, backup_ref):
    ref = str(backup_ref or "").strip().replace("\\", "/").lstrip("/")
    if not ref or ref in {".", ".."}:
        return None
    path = os.path.abspath(os.path.join(backup_dir, ref))
    root = os.path.abspath(backup_dir)
    if not (path == root or path.startswith(root + os.sep)):
        return None
    return path


def _node_backup_subdir(backup_dir, node_id, auto_groups):
    nid = _safe_file_name(node_id)
    for gid, gdata in (auto_groups or {}).items():
        if nid in (gdata.get("nodes", {}) or {}):
            return os.path.join(backup_dir, "group_nodes", _safe_file_name(gid), nid), f"group/{gid}/{nid}"
    return os.path.join(backup_dir, "custom_nodes", nid), f"custom/{nid}"


def create_node_backup_snapshot(backup_dir, node_id, db, auto_groups=None):
    safe_node = _safe_file_name(node_id)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"node_backup__{safe_node}__{timestamp}.json"
    subdir, folder_label = _node_backup_subdir(backup_dir, safe_node, auto_groups or {})
    os.makedirs(subdir, exist_ok=True)
    path = os.path.join(subdir, filename)

    users = {}
    for uname, info in (db or {}).items():
        if isinstance(info, dict) and str(info.get("node", "")).strip() == str(node_id).strip():
            users[uname] = info

    payload = {
        "type": "node_backup",
        "version": 1,
        "node_id": str(node_id),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "users": users
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    return _rel(path, backup_dir), len(users), folder_label


def create_full_backup_snapshot(backup_dir, payload):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"full_backup__{timestamp}.json"
    full_dir = os.path.join(backup_dir, "full_backups")
    os.makedirs(full_dir, exist_ok=True)
    path = os.path.join(full_dir, filename)
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    return _rel(path, backup_dir)


def read_backup_json(path):
    with open(path, "r") as f:
        return json.load(f)


def list_backups(backup_dir):
    node_backups = {}
    full_backups = []

    if not os.path.exists(backup_dir):
        return {"node_backups": node_backups, "full_backups": full_backups}

    all_files = []
    for root, _, files in os.walk(backup_dir):
        for filename in files:
            if filename.endswith(".json"):
                path = os.path.join(root, filename)
                if os.path.isfile(path):
                    all_files.append(path)

    all_files.sort(key=lambda p: os.path.getctime(p), reverse=True)

    for path in all_files:
        filename = os.path.basename(path)
        rel_ref = _rel(path, backup_dir)
        meta = {
            "ref": rel_ref,
            "filename": filename,
            "size": _fmt_size(path),
            "time": _fmt_time(path),
            "folder": os.path.dirname(rel_ref) or "."
        }

        if filename.startswith("full_backup__"):
            full_backups.append(meta)
            continue

        nid = _node_id_from_name(filename)
        if not nid:
            continue
        node_backups.setdefault(nid, []).append(meta)

    return {"node_backups": node_backups, "full_backups": full_backups}
