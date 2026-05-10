/**
 * PanelMaster API client for Node.js (v18+)
 *
 * Usage:
 *   const { PanelMasterClient } = require("./panelmaster-client");
 *   const client = new PanelMasterClient({
 *     baseUrl: "http://YOUR_PANEL_IP:8888",
 *     apiKey: "My_Super_Secret_VPN_Key_2026"
 *   });
 */

class PanelMasterClient {
  constructor({ baseUrl, apiKey, timeoutMs = 15000 }) {
    if (!baseUrl) throw new Error("baseUrl is required");
    if (!apiKey) throw new Error("apiKey is required");

    this.baseUrl = String(baseUrl).replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
  }

  async _request(path, { method = "GET", body, withApiKey = true } = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers = { "Content-Type": "application/json" };
      if (withApiKey) headers["x-api-key"] = this.apiKey;

      const res = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal
      });

      let data = null;
      try {
        data = await res.json();
      } catch (_) {
        data = null;
      }

      if (!res.ok) {
        const message =
          (data && (data.error || data.message)) || `HTTP ${res.status}`;
        throw new Error(`PanelMaster API error: ${message}`);
      }

      return data;
    } finally {
      clearTimeout(timer);
    }
  }

  // GET /api/active-groups
  async getActiveGroups() {
    return this._request("/api/active-groups");
  }

  // POST /api/generate-keys
  // returns: { success, keys, token }
  async createUser({
    masterGroupId,
    userName,
    totalGB = 50,
    expireDate // "YYYY-MM-DD"
  }) {
    if (!masterGroupId) throw new Error("masterGroupId is required");
    if (!userName) throw new Error("userName is required");

    return this._request("/api/generate-keys", {
      method: "POST",
      body: { masterGroupId, userName, totalGB, expireDate }
    });
  }

  // POST /api/webhook/switch
  async switchServer({ token, activeServer }) {
    if (!token) throw new Error("token is required");
    if (!activeServer) throw new Error("activeServer is required");

    return this._request("/api/webhook/switch", {
      method: "POST",
      body: { token, activeServer }
    });
  }

  // POST /api/user-action
  async userAction({ token, action }) {
    if (!token) throw new Error("token is required");
    if (!action) throw new Error("action is required");
    if (!["suspend", "resume", "delete"].includes(action)) {
      throw new Error("action must be suspend, resume, or delete");
    }

    return this._request("/api/user-action", {
      method: "POST",
      body: { token, action }
    });
  }

  async suspendUser(token) {
    return this.userAction({ token, action: "suspend" });
  }

  async resumeUser(token) {
    return this.userAction({ token, action: "resume" });
  }

  async deleteUser(token) {
    return this.userAction({ token, action: "delete" });
  }

  // GET /conf/<token>.json (no api key required)
  async getUserConfig(token) {
    if (!token) throw new Error("token is required");
    return this._request(`/conf/${encodeURIComponent(token)}.json`, {
      method: "GET",
      withApiKey: false
    });
  }
}

module.exports = { PanelMasterClient };

