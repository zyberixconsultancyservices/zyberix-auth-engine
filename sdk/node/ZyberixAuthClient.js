/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — OFFICIAL NODE.JS SDK
 *  File:      sdk/node/ZyberixAuthClient.js
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 *
 * Thin, dependency-free (native fetch) client for integrating any Node.js
 * application with a running Zyberix Auth Engine instance (Microservice
 * Engine or Light-Embed Engine's REST surface).
 *
 * Usage:
 *   const { ZyberixAuthClient } = require('./ZyberixAuthClient');
 *   const zyberix = new ZyberixAuthClient({ apiKey: process.env.ZYBERIX_API_KEY });
 *   const { verificationId } = await zyberix.triggerVerification('user_123', 'HIGH_RISK_ACTION');
 *   const { verified } = await zyberix.checkStatus(verificationId);
 */

class ZyberixApiError extends Error {
  /**
   * @param {string} message
   * @param {number} statusCode
   * @param {unknown} body
   */
  constructor(message, statusCode, body) {
    super(message);
    this.name = "ZyberixApiError";
    this.statusCode = statusCode;
    this.body = body;
  }
}

class ZyberixAuthClient {
  /**
   * @param {object} config
   * @param {string} config.apiKey - Your Zyberix Auth Engine API key.
   * @param {string} [config.baseUrl] - Engine base URL. Defaults to the managed cloud endpoint.
   * @param {number} [config.timeoutMs] - Request timeout in milliseconds. Default 8000.
   */
  constructor(config) {
    if (!config || !config.apiKey) {
      throw new Error("ZyberixAuthClient: 'apiKey' is required.");
    }
    this.apiKey = config.apiKey;
    this.baseUrl = (config.baseUrl || "https://engine.zyberix.io/api/v1").replace(/\/$/, "");
    this.timeoutMs = config.timeoutMs || 8000;
  }

  /**
   * @param {string} path
   * @param {object} [options]
   */
  async _request(path, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method: options.method || "GET",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
          "X-Powered-By": "Zyberix-Auth-Engine-v1.0",
          ...(options.headers || {}),
        },
        body: options.body ? JSON.stringify(options.body) : undefined,
        signal: controller.signal,
      });

      const contentType = response.headers.get("content-type") || "";
      const payload = contentType.includes("application/json") ? await response.json() : await response.text();

      if (!response.ok) {
        throw new ZyberixApiError(
          `Zyberix Auth Engine request failed with status ${response.status}`,
          response.status,
          payload
        );
      }
      return payload;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Triggers a two-factor action verification for a user via the given
   * channel (defaults to the account's configured preferred method).
   * @param {string} userId
   * @param {string} actionContext - e.g. 'HIGH_RISK_ACTION:wire_transfer'
   * @param {object} [options]
   * @param {'email'|'totp'|'whatsapp'|'telegram'|'webauthn'|'push'} [options.channel]
   * @returns {Promise<{verificationId: string, channel: string, expiresAt: string}>}
   */
  async triggerVerification(userId, actionContext, options = {}) {
    return this._request("/verifications", {
      method: "POST",
      body: { userId, actionContext, channel: options.channel },
    });
  }

  /**
   * Polls the current status of a verification request.
   * @param {string} verificationId
   * @returns {Promise<{verified: boolean, status: string, verifiedAt: string|null}>}
   */
  async checkStatus(verificationId) {
    return this._request(`/verifications/${encodeURIComponent(verificationId)}`);
  }

  /**
   * Submits a user-provided code (TOTP or reveal-link OTP) for verification.
   * @param {string} verificationId
   * @param {string} code
   */
  async submitCode(verificationId, code) {
    return this._request(`/verifications/${encodeURIComponent(verificationId)}/submit`, {
      method: "POST",
      body: { code },
    });
  }

  /**
   * Enrolls a new TOTP secret for a user and returns a QR-ready otpauth URI.
   * @param {string} userId
   */
  async enrollTotp(userId) {
    return this._request(`/totp/enroll`, { method: "POST", body: { userId } });
  }
}

module.exports = { ZyberixAuthClient, ZyberixApiError };
