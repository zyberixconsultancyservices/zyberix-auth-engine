/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — UTILITY MODULE
 *  File:      src/Utils/RateLimiter.ts
 *  Component: Sliding-Window Throttler & Circuit Breaker
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 *
 * IP- and user-scoped sliding-window rate limiting with an automated
 * brute-force circuit breaker: once a key exceeds `breakerThreshold`
 * failures inside `windowMs`, it is locked out for `cooldownMs` regardless
 * of subsequent successes, until the cooldown elapses.
 */

interface WindowEntry {
  timestamps: number[];
  breakerUntil: number | null;
}

export interface RateLimiterOptions {
  windowMs: number;
  maxRequests: number;
  breakerThreshold: number;
  cooldownMs: number;
}

const DEFAULTS: RateLimiterOptions = {
  windowMs: 60_000,
  maxRequests: 10,
  breakerThreshold: 20,
  cooldownMs: 15 * 60_000,
};

export class RateLimiter {
  private readonly store: Map<string, WindowEntry> = new Map();
  private readonly options: RateLimiterOptions;

  constructor(options: Partial<RateLimiterOptions> = {}) {
    this.options = { ...DEFAULTS, ...options };
  }

  private getEntry(key: string): WindowEntry {
    let entry = this.store.get(key);
    if (!entry) {
      entry = { timestamps: [], breakerUntil: null };
      this.store.set(key, entry);
    }
    return entry;
  }

  /**
   * Checks whether a request for `key` (e.g., `ip:203.0.113.4` or
   * `user:abc123`) is allowed right now, recording it if so.
   */
  public check(key: string): { allowed: boolean; retryAfterMs?: number; breakerActive?: boolean } {
    const now = Date.now();
    const entry = this.getEntry(key);

    if (entry.breakerUntil && entry.breakerUntil > now) {
      return { allowed: false, retryAfterMs: entry.breakerUntil - now, breakerActive: true };
    }
    if (entry.breakerUntil && entry.breakerUntil <= now) {
      entry.breakerUntil = null;
      entry.timestamps = [];
    }

    entry.timestamps = entry.timestamps.filter((ts) => now - ts < this.options.windowMs);

    if (entry.timestamps.length >= this.options.breakerThreshold) {
      entry.breakerUntil = now + this.options.cooldownMs;
      return { allowed: false, retryAfterMs: this.options.cooldownMs, breakerActive: true };
    }

    if (entry.timestamps.length >= this.options.maxRequests) {
      const oldest = entry.timestamps[0];
      return { allowed: false, retryAfterMs: this.options.windowMs - (now - oldest) };
    }

    entry.timestamps.push(now);
    return { allowed: true };
  }

  /** Clears throttling state for a key (e.g., after a confirmed legitimate action). */
  public reset(key: string): void {
    this.store.delete(key);
  }
}
