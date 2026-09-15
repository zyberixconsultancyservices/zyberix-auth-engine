/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — CORE SECURITY MODULE
 *  File:      src/Security/ZyberixCryptoEngine.ts
 *  Component: Cryptographic Core
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 *
 * Provides authenticated encryption (AES-256-GCM), HMAC signing/verification,
 * and key-rotation primitives used across every verification module in the
 * Zyberix Auth Engine. This module never persists plaintext secrets; callers
 * are expected to discard plaintext buffers immediately after use.
 *
 * Standards referenced:
 *   - NIST SP 800-38D (GCM mode of operation)
 *   - FIPS 198-1      (HMAC)
 */

import { randomBytes, createCipheriv, createDecipheriv, createHmac, timingSafeEqual } from "crypto";

/** Banner emitted in logs/headers to identify the engine build. */
export const ZYBERIX_BUILD_BANNER = "Zyberix-Auth-Engine-v1.0 :: CryptoCore/AES-256-GCM";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH_BYTES = 12; // 96-bit IV recommended for GCM
const AUTH_TAG_LENGTH_BYTES = 16;
const KEY_LENGTH_BYTES = 32; // 256-bit key

/** Shape of an encrypted envelope produced by this engine. */
export interface ZyberixCipherEnvelope {
  /** Key identifier used for this encryption, enabling rotation without breaking old data. */
  keyId: string;
  /** Base64 initialization vector. */
  iv: string;
  /** Base64 GCM authentication tag. */
  authTag: string;
  /** Base64 ciphertext. */
  ciphertext: string;
  /** ISO-8601 timestamp of encryption, for audit correlation. */
  encryptedAt: string;
}

/** A single named key in the active key ring. */
interface KeyRingEntry {
  keyId: string;
  key: Buffer;
  createdAt: Date;
}

/**
 * ZyberixCryptoEngine
 *
 * Manages a rotating ring of AES-256 keys and exposes encrypt/decrypt/sign
 * operations. Only the active (most recently added) key is used for new
 * encryptions; older keys remain available for decrypting existing data
 * until explicitly retired by the caller.
 */
export class ZyberixCryptoEngine {
  private readonly keyRing: Map<string, KeyRingEntry> = new Map();
  private activeKeyId: string | null = null;

  /**
   * @param initialKey Optional raw 32-byte key to seed the ring with. If
   *   omitted, a new key is generated and becomes active immediately.
   * @param initialKeyId Optional identifier for the seeded key.
   */
  constructor(initialKey?: Buffer, initialKeyId?: string) {
    if (initialKey) {
      this.addKey(initialKey, initialKeyId ?? ZyberixCryptoEngine.generateKeyId());
    } else {
      this.rotateKey();
    }
  }

  /** Generates a cryptographically random 256-bit key. */
  public static generateKey(): Buffer {
    return randomBytes(KEY_LENGTH_BYTES);
  }

  /** Generates a short, collision-resistant key identifier. */
  public static generateKeyId(): string {
    return `zbx_${randomBytes(6).toString("hex")}`;
  }

  /**
   * Registers a new key into the ring and immediately promotes it to active,
   * so all subsequent encryptions use it. Prior keys are retained for
   * decrypting historical envelopes.
   */
  public addKey(key: Buffer, keyId: string): void {
    if (key.length !== KEY_LENGTH_BYTES) {
      throw new Error(`Zyberix CryptoEngine: key must be ${KEY_LENGTH_BYTES} bytes (256-bit).`);
    }
    this.keyRing.set(keyId, { keyId, key, createdAt: new Date() });
    this.activeKeyId = keyId;
  }

  /**
   * Generates and activates a brand-new key. Intended to be called on a
   * scheduled rotation cadence (e.g., every 30/60/90 days) by an operator
   * job, not on every request.
   */
  public rotateKey(): string {
    const keyId = ZyberixCryptoEngine.generateKeyId();
    this.addKey(ZyberixCryptoEngine.generateKey(), keyId);
    return keyId;
  }

  /** Permanently removes a retired key. Fails closed if it is still active. */
  public retireKey(keyId: string): void {
    if (keyId === this.activeKeyId) {
      throw new Error("Zyberix CryptoEngine: cannot retire the active key. Rotate first.");
    }
    this.keyRing.delete(keyId);
  }

  private getKeyOrThrow(keyId: string): KeyRingEntry {
    const entry = this.keyRing.get(keyId);
    if (!entry) {
      throw new Error(`Zyberix CryptoEngine: unknown keyId "${keyId}". It may have been retired.`);
    }
    return entry;
  }

  /**
   * Encrypts plaintext with the currently active key using AES-256-GCM.
   * @param plaintext Raw data to encrypt (e.g., a serialized secret record).
   * @returns A self-describing cipher envelope.
   */
  public encrypt(plaintext: string | Buffer): ZyberixCipherEnvelope {
    if (!this.activeKeyId) {
      throw new Error("Zyberix CryptoEngine: no active key configured.");
    }
    const { key, keyId } = this.getKeyOrThrow(this.activeKeyId);
    const iv = randomBytes(IV_LENGTH_BYTES);
    const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH_BYTES });

    const inputBuffer = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : plaintext;
    const ciphertext = Buffer.concat([cipher.update(inputBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      keyId,
      iv: iv.toString("base64"),
      authTag: authTag.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
      encryptedAt: new Date().toISOString(),
    };
  }

  /**
   * Decrypts a previously produced envelope. Uses the keyId embedded in the
   * envelope, so rotation does not break decryption of older data.
   * @throws if the auth tag fails verification (tamper detection).
   */
  public decrypt(envelope: ZyberixCipherEnvelope): Buffer {
    const { key } = this.getKeyOrThrow(envelope.keyId);
    const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(envelope.iv, "base64"), {
      authTagLength: AUTH_TAG_LENGTH_BYTES,
    });
    decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));

    return Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64")),
      decipher.final(),
    ]);
  }

  /**
   * Produces an HMAC-SHA256 signature over a payload using the active key.
   * Used for signing webhook payloads and reveal-link tokens.
   */
  public sign(payload: string | Buffer): string {
    if (!this.activeKeyId) {
      throw new Error("Zyberix CryptoEngine: no active key configured.");
    }
    const { key } = this.getKeyOrThrow(this.activeKeyId);
    return createHmac("sha256", key).update(payload).digest("base64url");
  }

  /**
   * Verifies an HMAC-SHA256 signature in constant time to avoid timing
   * side-channels during comparison.
   */
  public verify(payload: string | Buffer, signature: string, keyId?: string): boolean {
    const targetKeyId = keyId ?? this.activeKeyId;
    if (!targetKeyId) return false;
    const { key } = this.getKeyOrThrow(targetKeyId);
    const expected = createHmac("sha256", key).update(payload).digest();
    let provided: Buffer;
    try {
      provided = Buffer.from(signature, "base64url");
    } catch {
      return false;
    }
    if (provided.length !== expected.length) return false;
    return timingSafeEqual(provided, expected);
  }

  /** Returns the identifier of the currently active key (safe to log). */
  public getActiveKeyId(): string | null {
    return this.activeKeyId;
  }
}
