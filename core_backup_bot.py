import json
import os
import threading
import time
import requests


_scheduler_started = False
_scheduler_lock = threading.Lock()


def _extract_backup_parts(backup_result):
    if not isinstance(backup_result, tuple):
        return None, None, None
    if len(backup_result) >= 3:
        return backup_result[0], backup_result[1], backup_result[2]
    if len(backup_result) == 2:
        return backup_result[0], backup_result[1], None
    return None, None, None


def _telegram_api_post(bot_token, method, data=None, timeout=30):
    token = str(bot_token or "").strip()
    if not token:
        return False, "empty token", {}
    url = f"https://api.telegram.org/bot{token}/{method}"
    try:
        res = requests.post(url, data=data or {}, timeout=timeout)
        if 200 <= res.status_code < 300:
            payload = {}
            try:
                payload = res.json()
            except Exception:
                payload = {}
            return True, "ok", payload
        return False, f"http {res.status_code}: {res.text[:200]}", {}
    except Exception as e:
        return False, str(e), {}


def _notify_admin_text(bot_token, admin_id, text):
    _telegram_api_post(
        bot_token,
        "sendMessage",
        data={"chat_id": str(admin_id or "").strip(), "text": str(text or "")[:3500]},
        timeout=20
    )


def _telegram_get_updates(bot_token, offset=None, timeout=20):
    token = str(bot_token or "").strip()
    if not token:
        return False, "empty token", []
    url = f"https://api.telegram.org/bot{token}/getUpdates"
    params = {"timeout": timeout}
    if offset is not None:
        params["offset"] = int(offset)
    try:
        res = requests.get(url, params=params, timeout=timeout + 10)
        if not (200 <= res.status_code < 300):
            return False, f"http {res.status_code}: {res.text[:200]}", []
        payload = res.json() or {}
        if not payload.get("ok", False):
            return False, str(payload.get("description") or "telegram getUpdates failed"), []
        updates = payload.get("result", [])
        if not isinstance(updates, list):
            updates = []
        return True, "ok", updates
    except Exception as e:
        return False, str(e), []


def _send_bot_controls(bot_token, chat_id):
    inline = {
        "inline_keyboard": [
            [{"text": "Backup Now", "callback_data": "backup_now"}]
        ]
    }
    reply = {
        "keyboard": [
            [{"text": "Backup Now"}]
        ],
        "resize_keyboard": True
    }
    _telegram_api_post(
        bot_token,
        "sendMessage",
        data={
            "chat_id": chat_id,
            "text": "PanelMaster Backup Bot ready.\nTap Backup Now for manual full backup.",
            "reply_markup": json.dumps(inline)
        },
        timeout=20
    )
    _telegram_api_post(
        bot_token,
        "sendMessage",
        data={
            "chat_id": chat_id,
            "text": "Quick action keyboard enabled.",
            "reply_markup": json.dumps(reply)
        },
        timeout=20
    )


def _run_manual_backup_from_bot(bot_token, chat_id, create_backup_file_fn, log_fn=None):
    try:
        backup_result = create_backup_file_fn("manual_telegram_bot")
        backup_ref, backup_path, user_count = _extract_backup_parts(backup_result)
        if not backup_ref or not backup_path:
            return False, "backup creation failed"
        users_text = ""
        if isinstance(user_count, int):
            users_text = f"\nUsers: {user_count}"
        ok, msg = send_backup_to_telegram(
            bot_token,
            chat_id,
            backup_path,
            caption=f"PanelMaster Manual Backup\nFile: {backup_ref}{users_text}"
        )
        if ok:
            if log_fn:
                log_fn("Backup Bot", f"Manual backup sent from Telegram: {backup_ref}", "success")
            return True, "sent"
        if log_fn:
            log_fn("Backup Bot", f"Manual backup from Telegram failed: {msg}", "error")
        return False, msg
    except Exception as e:
        if log_fn:
            log_fn("Backup Bot", f"Manual backup from Telegram error: {e}", "error")
        return False, str(e)


def send_backup_to_telegram(bot_token, admin_id, file_path, caption=""):
    token = str(bot_token or "").strip()
    chat_id = str(admin_id or "").strip()
    if not token or not chat_id:
        return False, "backup bot token/admin id is empty"
    if not file_path or not os.path.exists(file_path):
        return False, "backup file not found"

    url = f"https://api.telegram.org/bot{token}/sendDocument"
    try:
        with open(file_path, "rb") as fp:
            files = {"document": fp}
            data = {"chat_id": chat_id, "caption": caption[:1024]}
            res = requests.post(url, data=data, files=files, timeout=45)
        if 200 <= res.status_code < 300:
            return True, "ok"
        return False, f"http {res.status_code}: {res.text[:200]}"
    except Exception as e:
        return False, str(e)


def start_backup_scheduler(load_config_fn, save_config_fn, create_backup_file_fn, log_fn=None, poll_seconds=60):
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        _scheduler_started = True

    def _log(msg, level="info"):
        if log_fn:
            try:
                log_fn("Backup Bot", msg, level)
            except Exception:
                pass

    def _worker():
        while True:
            try:
                cfg = load_config_fn() or {}
                enabled = bool(cfg.get("backup_bot_enabled", False))
                token = str(cfg.get("backup_bot_token", "")).strip()
                admin_id = str(cfg.get("backup_bot_admin_id", "")).strip()

                try:
                    interval_minutes = float(cfg.get("backup_bot_interval_minutes", 0) or 0)
                except Exception:
                    interval_minutes = 0.0
                if interval_minutes <= 0:
                    # Backward-compatible fallback for old configs.
                    try:
                        hours = float(cfg.get("backup_bot_interval_hours", 1) or 1)
                    except Exception:
                        hours = 1.0
                    interval_minutes = max(1.0, hours * 60.0)
                interval_minutes = max(1.0, interval_minutes)
                try:
                    last_sent = float(cfg.get("backup_bot_last_sent_ts", 0) or 0)
                except Exception:
                    last_sent = 0.0
                now = time.time()
                if last_sent > now + 300:
                    # Defensive: if timestamp is accidentally in the future, do not stall autosend.
                    last_sent = 0.0

                due = enabled and token and admin_id and (now - last_sent >= interval_minutes * 60.0)
                if due:
                    backup_result = create_backup_file_fn("auto_telegram")
                    backup_ref, backup_path, _ = _extract_backup_parts(backup_result)
                    if not backup_ref or not backup_path:
                        _log("Auto backup skipped: invalid backup result", "error")
                        time.sleep(max(20, int(poll_seconds)))
                        continue
                    ok, msg = send_backup_to_telegram(
                        token,
                        admin_id,
                        backup_path,
                        caption=f"PanelMaster Auto Backup\nFile: {backup_ref}"
                    )
                    if ok:
                        cfg["backup_bot_last_sent_ts"] = now
                        save_config_fn(cfg)
                        _log(f"Auto backup sent: {backup_ref}", "success")
                    else:
                        _log(f"Auto backup send failed: {msg}", "error")
                        _notify_admin_text(token, admin_id, f"Auto backup failed: {msg[:240]}")
            except Exception as e:
                _log(f"Scheduler error: {e}", "error")

            time.sleep(max(5, int(poll_seconds)))

    def _bot_listener():
        while True:
            try:
                cfg = load_config_fn() or {}
                token = str(cfg.get("backup_bot_token", "")).strip()
                admin_id = str(cfg.get("backup_bot_admin_id", "")).strip()
                # Manual Telegram commands should work even when auto-send is disabled.
                if not token or not admin_id:
                    time.sleep(5)
                    continue

                try:
                    last_update_id = int(cfg.get("backup_bot_last_update_id", 0) or 0)
                except Exception:
                    last_update_id = 0

                ok, msg, updates = _telegram_get_updates(
                    token,
                    offset=(last_update_id + 1) if last_update_id > 0 else None,
                    timeout=20
                )
                if not ok:
                    _log(f"Bot listener error: {msg}", "error")
                    time.sleep(5)
                    continue

                max_update_id = last_update_id
                for upd in updates:
                    if not isinstance(upd, dict):
                        continue
                    uid = int(upd.get("update_id", 0) or 0)
                    if uid > max_update_id:
                        max_update_id = uid

                    msg_obj = upd.get("message") or {}
                    cb_obj = upd.get("callback_query") or {}

                    if isinstance(msg_obj, dict) and msg_obj:
                        chat = msg_obj.get("chat") or {}
                        chat_id = str(chat.get("id", "")).strip()
                        text = str(msg_obj.get("text", "")).strip()
                        text_l = text.lower()
                        if chat_id != admin_id:
                            continue
                        if text_l in ("/start", "/help", "start", "help"):
                            _send_bot_controls(token, admin_id)
                        elif text_l in ("/backup", "/backup_now", "/backupnow", "backup now", "backup"):
                            _telegram_api_post(
                                token,
                                "sendMessage",
                                data={"chat_id": admin_id, "text": "Creating backup..."},
                                timeout=20
                            )
                            done, detail = _run_manual_backup_from_bot(token, admin_id, create_backup_file_fn, log_fn=log_fn)
                            if done:
                                cfg2 = load_config_fn() or {}
                                cfg2["backup_bot_last_sent_ts"] = time.time()
                                save_config_fn(cfg2)
                            else:
                                _telegram_api_post(
                                    token,
                                    "sendMessage",
                                    data={"chat_id": admin_id, "text": f"Backup failed: {detail[:180]}"},
                                    timeout=20
                                )

                    if isinstance(cb_obj, dict) and cb_obj:
                        data = str(cb_obj.get("data", "")).strip().lower()
                        cb_id = str(cb_obj.get("id", "")).strip()
                        cb_msg = cb_obj.get("message") or {}
                        cb_chat = cb_msg.get("chat") or {}
                        cb_chat_id = str(cb_chat.get("id", "")).strip()
                        if cb_id:
                            _telegram_api_post(
                                token,
                                "answerCallbackQuery",
                                data={"callback_query_id": cb_id, "text": "Processing..."},
                                timeout=15
                            )
                        if cb_chat_id != admin_id:
                            continue
                        if data == "backup_now":
                            done, detail = _run_manual_backup_from_bot(token, admin_id, create_backup_file_fn, log_fn=log_fn)
                            if done:
                                cfg2 = load_config_fn() or {}
                                cfg2["backup_bot_last_sent_ts"] = time.time()
                                save_config_fn(cfg2)
                            else:
                                _telegram_api_post(
                                    token,
                                    "sendMessage",
                                    data={"chat_id": admin_id, "text": f"Backup failed: {detail[:180]}"},
                                    timeout=20
                                )

                if max_update_id > last_update_id:
                    cfg["backup_bot_last_update_id"] = max_update_id
                    save_config_fn(cfg)
            except Exception as e:
                _log(f"Bot listener crash: {e}", "error")
                time.sleep(5)

    threading.Thread(target=_worker, daemon=True).start()
    threading.Thread(target=_bot_listener, daemon=True).start()
