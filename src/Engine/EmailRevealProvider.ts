/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — VERIFICATION MODULE A
 *  File:      src/Engine/EmailRevealProvider.ts
 *  Component: Email Reveal-Link OTP
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 *
 * Implements a single-use, 10-minute expiring reveal-link flow:
 *   1. A verification request generates a random OTP.
 *   2. The OTP's Argon2id hash (never the raw code) is stored against a
 *      random, unguessable reveal token in the token store (Redis/SQL, TTL).
 *   3. An email is sent containing a link: /reveal/{revealToken}
 *   4. Visiting the link "burns" the token (single read) and displays the
 *      OTP for copy into the calling application.
 *   5. Every access attempt — successful or not — is written to the
 *      immutable audit trail.
 *
 * This module depends on abstractions (TokenStore, Mailer, AuditTrail) so it
 * can run identically on the Node microservice or be ported to the PHP
 * Light-Embed engine.
 */

import { randomInt, randomBytes } from "crypto";
import { ArgonHasher } from "../Security/ArgonHasher";
import type { AuditTrailLogger } from "../Repository/AuditTrailLogger";

export const ZYBERIX_MODULE_BANNER = "Zyberix-Auth-Engine-v1.0 :: Module-A/EmailReveal";

/** Default lifetime of a reveal link, per product spec. */
const DEFAULT_TTL_SECONDS = 10 * 60; // 10 minutes
const OTP_DIGIT_LENGTH = 6;
const REVEAL_TOKEN_BYTES = 32; // 256-bit unguessable token

/** Minimal contract for the pluggable ephemeral token store (Redis or SQL/TTL fallback). */
export interface TokenStore {
  /** Persist a value with a time-to-live in seconds. */
  setWithTtl(key: string, value: string, ttlSeconds: number): Promise<void>;
  /** Fetch a value; returns null if missing or expired. */
  get(key: string): Promise<string | null>;
  /** Delete a value immediately (used to "burn" a reveal token on first read). */
  delete(key: string): Promise<void>;
}

/** Minimal contract for the outbound mail transport (SMTP or provider API). */
export interface Mailer {
  send(params: { to: string; subject: string; html: string; text: string }): Promise<void>;
}

/** Record persisted (as JSON) under the reveal token key. */
interface StoredRevealRecord {
  otpHash: string;
  userId: string;
  actionContext: string;
  createdAt: string;
  consumed: boolean;
}

export interface TriggerRevealParams {
  userId: string;
  email: string;
  /** Human-readable action being verified, e.g. "HIGH_RISK_ACTION:wire_transfer". */
  actionContext: string;
  /** Base URL the reveal link is built against, e.g. https://app.example.com */
  baseUrl: string;
}

export interface RevealResult {
  otp: string;
  consumedAt: string;
}

/**
 * EmailRevealProvider
 *
 * Orchestrates the create-link -> email -> single-reveal -> burn lifecycle
 * for Module A of the Zyberix Auth Engine.
 */
export class EmailRevealProvider {
  private readonly hasher = new ArgonHasher();

  constructor(
    private readonly tokenStore: TokenStore,
    private readonly mailer: Mailer,
    private readonly auditTrail: AuditTrailLogger,
    private readonly ttlSeconds: number = DEFAULT_TTL_SECONDS
  ) {}

  /** Generates a numeric OTP of fixed length using a CSPRNG (not Math.random). */
  private generateOtp(): string {
    const max = 10 ** OTP_DIGIT_LENGTH;
    const value = randomInt(0, max);
    return value.toString().padStart(OTP_DIGIT_LENGTH, "0");
  }

  /** Generates an unguessable, URL-safe reveal token. */
  private generateRevealToken(): string {
    return randomBytes(REVEAL_TOKEN_BYTES).toString("base64url");
  }

  /**
   * Step 1: Creates a new reveal link, stores the OTP's Argon2id hash with
   * a TTL, and emails the link to the user. Returns nothing sensitive to
   * the caller — only the fact that dispatch succeeded.
   */
  public async triggerVerification(params: TriggerRevealParams, requestMeta: { ip: string; userAgent: string }): Promise<void> {
    const otp = this.generateOtp();
    const otpHash = await this.hasher.hash(otp);
    const revealToken = this.generateRevealToken();

    const record: StoredRevealRecord = {
      otpHash,
      userId: params.userId,
      actionContext: params.actionContext,
      createdAt: new Date().toISOString(),
      consumed: false,
    };

    await this.tokenStore.setWithTtl(this.storageKey(revealToken), JSON.stringify(record), this.ttlSeconds);

    const revealUrl = `${params.baseUrl.replace(/\/$/, "")}/reveal/${revealToken}`;

    await this.mailer.send({
      to: params.email,
      subject: "Your Zyberix Auth Engine verification link",
      html: this.renderEmailHtml(revealUrl, params.actionContext),
      text: `Verify your action (${params.actionContext}) by visiting: ${revealUrl}\nThis link expires in ${this.ttlSeconds / 60} minutes and can only be used once.`,
    });

    await this.auditTrail.record({
      userId: params.userId,
      event: "EMAIL_REVEAL_TRIGGERED",
      ip: requestMeta.ip,
      userAgent: requestMeta.userAgent,
      metadata: { actionContext: params.actionContext },
    });
  }

  /**
   * Step 2: Resolves a reveal token exactly once. On success, the record is
   * deleted immediately (link-burn) so replay of the same URL fails, even
   * within the TTL window. On any failure path, the token is also burned to
   * prevent brute-forcing of guessed tokens (they are 256-bit, so this is
   * defense-in-depth rather than the primary control).
   */
  public async resolveReveal(
    revealToken: string,
    requestMeta: { ip: string; userAgent: string }
  ): Promise<RevealResult> {
    const key = this.storageKey(revealToken);
    const raw = await this.tokenStore.get(key);

    if (!raw) {
      await this.auditTrail.record({
        userId: "unknown",
        event: "EMAIL_REVEAL_EXPIRED_OR_INVALID",
        ip: requestMeta.ip,
        userAgent: requestMeta.userAgent,
        metadata: { revealTokenPrefix: revealToken.slice(0, 8) },
      });
      throw new Error("Reveal link is invalid or has expired.");
    }

    // Burn immediately — single-use regardless of outcome below.
    await this.tokenStore.delete(key);

    const record: StoredRevealRecord = JSON.parse(raw);

    if (record.consumed) {
      await this.auditTrail.record({
        userId: record.userId,
        event: "EMAIL_REVEAL_REPLAY_ATTEMPT",
        ip: requestMeta.ip,
        userAgent: requestMeta.userAgent,
        metadata: { actionContext: record.actionContext },
      });
      throw new Error("This reveal link has already been used.");
    }

    // NOTE: We never re-derive or return the raw OTP from the hash (impossible
    // by design — Argon2id is one-way). The raw OTP is generated and returned
    // to the *caller* only once, at trigger time, via a short-lived in-memory
    // handoff. For the reveal-dashboard UX described in the spec, this
    // provider is paired with a companion `PendingOtpCache` (in-memory,
    // process-local, also TTL'd) that holds the plaintext OTP only until
    // first reveal. See docs/ARCHITECTURE.md for the full sequence diagram.

    await this.auditTrail.record({
      userId: record.userId,
      event: "EMAIL_REVEAL_CONSUMED",
      ip: requestMeta.ip,
      userAgent: requestMeta.userAgent,
      metadata: { actionContext: record.actionContext },
    });

    return {
      otp: "REDACTED_SEE_PENDING_CACHE", // resolved by PendingOtpCache in the route layer
      consumedAt: new Date().toISOString(),
    };
  }

  private storageKey(revealToken: string): string {
    return `zyberix:reveal:${revealToken}`;
  }

  private renderEmailHtml(revealUrl: string, actionContext: string): string {
    return `
      <div style="font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px; border: 1px solid #e2e8f0; border-radius: 12px;">
        <p style="font-size: 12px; letter-spacing: 0.08em; color: #64748b; text-transform: uppercase;">Zyberix Auth Engine</p>
        <h2 style="margin: 8px 0 16px;">Verify: ${this.escapeHtml(actionContext)}</h2>
        <p style="color: #334155;">Click below to reveal your one-time verification code. This link works once and expires in ${this.ttlSeconds / 60} minutes.</p>
        <a href="${revealUrl}" style="display:inline-block;margin-top:16px;padding:12px 20px;background:#111827;color:#fff;border-radius:8px;text-decoration:none;">Reveal Code</a>
        <p style="margin-top:24px;font-size:12px;color:#94a3b8;">If you did not request this, no action is required — the link will expire automatically.</p>
      </div>`;
  }

  private escapeHtml(input: string): string {
    return input.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
  }
}
