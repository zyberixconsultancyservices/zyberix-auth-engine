/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — SECURITY MODULE
 *  File:      src/Security/ArgonHasher.ts
 *  Component: Secret Hashing (Argon2id)
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 *
 * Wraps Argon2id (via the `argon2` npm package, libsodium bindings) for
 * hashing one-time codes and recovery secrets before they are persisted.
 * Zyberix Auth Engine NEVER stores a raw OTP or secret — only its Argon2id
 * hash — so a database compromise alone cannot yield usable codes.
 *
 * Tuning defaults follow OWASP Password Storage Cheat Sheet guidance for
 * Argon2id (2024 revision): memoryCost 19 MiB minimum for interactive auth;
 * this module defaults higher since verification codes are low-frequency,
 * high-value operations.
 */

import * as argon2 from "argon2";

/** Tunable Argon2id cost parameters. */
export interface ArgonHashOptions {
  /** Memory cost in KiB. Default: 65536 (64 MiB). */
  memoryCost?: number;
  /** Number of iterations. Default: 3. */
  timeCost?: number;
  /** Degree of parallelism. Default: 2. */
  parallelism?: number;
}

const DEFAULT_OPTIONS: Required<ArgonHashOptions> = {
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 2,
};

export class ArgonHasher {
  private readonly options: Required<ArgonHashOptions>;

  constructor(options: ArgonHashOptions = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
  }

  /**
   * Hashes a secret (OTP, recovery code, TOTP seed backup, etc.) with
   * Argon2id. The returned string is self-describing (includes the salt
   * and parameters) and safe to store directly in a database column.
   */
  public async hash(secret: string): Promise<string> {
    return argon2.hash(secret, {
      type: argon2.argon2id,
      memoryCost: this.options.memoryCost,
      timeCost: this.options.timeCost,
      parallelism: this.options.parallelism,
    });
  }

  /**
   * Verifies a plaintext secret against a previously stored Argon2id hash.
   * Returns false (never throws) on malformed hashes to avoid leaking
   * internal state through exception types/timing.
   */
  public async verify(storedHash: string, candidate: string): Promise<boolean> {
    try {
      return await argon2.verify(storedHash, candidate);
    } catch {
      return false;
    }
  }
}
