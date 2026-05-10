# PanelMaster Integration Spec (Master <-> External Panel)

This document is for the external panel developer.

## 1) Auth and Common Headers

- Required header on protected endpoints:
  - `Content-Type: application/json`
  - `x-api-key: <PANELMASTER_API_KEY>`
- Store API key in environment variable (never hardcode).

```js
const headers = {
  "Content-Type": "application/json",
  "x-api-key": process.env.PANELMASTER_API_KEY
};
```

---

## 2) Master -> External GB Sync (IMPORTANT)

Master pushes user usage to external panel (webhook style).

### URL order used by Master

1. `POST /api/internal/sync-user-usage`
2. fallback `POST /admin/api/internal/sync-user-usage`

Keep at least route (1). Best: support both.

### Payload sent by Master

```json
{
  "name": "username",
  "usedGB": 12.3456,
  "totalGB": 50,
  "remainingGB": 37.6544,
  "expireDate": "2026-04-30",
  "isBlocked": false,
  "isActive": true,
  "node": "Node3",
  "group": "Test_1"
}
```

### Send trigger in Master

Master sends when user has new traffic and at least one condition is true:
- 30 seconds passed since last sync, or
- new usage since last sync >= 50 MB.

### Expected external behavior

- Verify `x-api-key`.
- Validate payload (`name` required).
- Upsert/update external user by username (`name`).
- Save: `usedGB`, `totalGB`, `remainingGB`, `expireDate`, `isBlocked`.
- Return fast `200` (or `204`).

### Node.js receiver example (Express)

```js
app.post(
  ["/api/internal/sync-user-usage", "/admin/api/internal/sync-user-usage"],
  async (req, res) => {
    const apiKey = req.header("x-api-key");
    if (apiKey !== process.env.PANELMASTER_API_KEY) {
      return res.status(401).json({ ok: false, error: "invalid_api_key" });
    }

    const { name, usedGB, totalGB, remainingGB, expireDate, isBlocked } = req.body || {};
    if (!name) return res.status(400).json({ ok: false, error: "name_required" });

    await updateUserUsageFromMaster({
      username: String(name),
      usedGB: Number(usedGB || 0),
      totalGB: Number(totalGB || 0),
      remainingGB: Number(remainingGB || 0),
      expireDate: expireDate || null,
      isBlocked: Boolean(isBlocked)
    });

    return res.status(200).json({ ok: true });
  }
);
```

---

## 2B) Master -> External `sync-new-server` (Group Node Sync)

When Master adds/syncs a node inside an auto group, it pushes this webhook.

### Trigger events

- New node added to a group
- Node reinstalled
- Manual "Sync" button pressed in group UI
- Any event that changes node config for a group

### URL used by Master

- `POST https://dash1.dabazinme.me/api/internal/sync-new-server`
- Configurable via `external_new_server_sync_url` in config or env `PANEL_SYNC_NEW_SERVER_URL`

### Headers

```
Content-Type: application/json
x-api-key: pmk_XI1fBk3DEEekIDwgngJWQmjFXR0TziWkzw9UvmNB_Uk
```

### Payload sent by Master

```json
{
  "masterGroupId": "Test_1",
  "groupName": "Test_1",
  "version": "2026-04-02T18:00:00Z#sg3",
  "at": "2026-04-02T18:00:00Z",
  "newServerId": "sg3",
  "newServerDisplayName": "Singapore-3",
  "userKeys": {
    "alice": {
      "server": "1.2.3.4",
      "server_port": 10001,
      "password": "alice-uuid-here",
      "method": "chacha20-ietf-poly1305",
      "prefix": "\u0016\u0003\u0001\u0005\u00f2\u0001\u0000\u0005\u00ee\u0003\u0003"
    },
    "bob": {
      "server": "1.2.3.4",
      "server_port": 10002,
      "password": "bob-uuid-here",
      "method": "chacha20-ietf-poly1305",
      "prefix": "\u0016\u0003\u0001\u0005\u00f2\u0001\u0000\u0005\u00ee\u0003\u0003"
    },
    "charlie": "vless://uuid@1.2.3.4:8080?type=ws&path=/vless#charlie"
  }
}
```

### CRITICAL RULES

1. **`userKeys` contains EVERY user in the group**, not a subset.
   Each key = exact local username. Each value = that user's individual
   SS config object (or VLESS URL string) for the new node.
   If a user is missing, that user will NOT get the new node.

2. **`masterGroupId`** must match exactly with external panel DB.

3. **`newServerId`** = node ID (primary key).
   **`newServerDisplayName`** = human-readable label (for UI only).

4. **`version`** = `"<ISO_timestamp>#<node_id>"` — tracking field.
   **`at`** = `"<ISO_timestamp>"` — event timestamp (UTC).

### Expected external behavior

- Verify `x-api-key`.
- Validate required: `masterGroupId`, `newServerId`, `userKeys`.
- Use `newServerId` as primary ID key (do not map by display name).
- Use `newServerDisplayName` only for UI text.
- Return `200` with `{"success": true}`.
- `400` = missing fields, `404` = unknown masterGroupId, `401` = wrong key.

---

## 3) External -> Master API Endpoints

### A) Get active groups
- `GET /api/active-groups`

### B) Generate keys
- `POST /api/generate-keys`
- request:
```json
{
  "masterGroupId": "group_id",
  "userName": "username",
  "totalGB": 50,
  "expireDate": "2026-04-30"
}
```

### C) Switch active server
- `POST /api/webhook/switch`
```json
{
  "token": "user_token",
  "activeServer": "NodeNameOrNodeId"
}
```

### D) User action (suspend/resume/delete)
- `POST /api/user-action`
```json
{
  "token": "user_token",
  "action": "suspend"
}
```
- action aliases:
  - suspend: `suspend`, `block`, `blocked`, `pause`
  - resume: `resume`, `unblock`, `unblocked`, `unpause`
  - delete: `delete`

### E) Internal edit user
- `POST /api/internal/edit-user`
```json
{
  "username": "user1",
  "totalGB": 100,
  "usedGB": 12.5,
  "expireDate": "2026-05-01"
}
```

### F) Internal block user
- `POST /api/internal/block-user`
```json
{
  "username": "user1"
}
```

### G) Internal delete user
- `POST /api/internal/delete-user`
```json
{
  "username": "user1"
}
```
or
```json
{
  "token": "user_token"
}
```

---

## 4) Status Codes and Retry Policy

- `200`/`204`: success
- `400`: bad payload (do not blind-retry)
- `401`: invalid/revoked key (stop retries, rotate key)
- `404`: user/group not found (investigate mapping)
- `500`: temporary server error (retry with backoff)

---

## 5) API Key Rotation Checklist

1. Update external env: `PANELMASTER_API_KEY`
2. Restart external service
3. Test protected endpoint (`/api/active-groups`)
4. Confirm usage webhook receives `200`

---

## 6) Duplicate Usernames Across Groups

Master Panel supports the **same username in different auto-node groups**.

- Internal DB key: `group_id::username` (e.g. `Group_A::alice`, `Group_B::alice`)
- External-facing payloads always send the **display username** (e.g. `alice`) plus the **group** field
- The external panel should use `group + username` as the composite unique key
- Backward compatible: existing entries without `::` continue to work

---

## 7) Reverse Proxy / WAF Note

If using Cloudflare/WAF, allow API routes and custom header `x-api-key` for:
- `/api/*`
- `/admin/api/*`
