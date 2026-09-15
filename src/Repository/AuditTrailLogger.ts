/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — COMPLIANCE MODULE
 *  File:      src/Repository/AuditTrailLogger.ts
 *  Component: Immutable Audit Trail
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 *
 * Persists append-only audit entries for every security-relevant event
 * (link triggers, reveals, TOTP checks, WebAuthn ceremonies, push approvals).
 * IP addresses and user agents are stored only as SHA-256 hashes so the log
 * itself cannot be mined for raw PII, while still supporting equality checks
 * (e.g., "was this the same IP as the trigger event?").
 */

import { createHash } from "crypto";

export interface AuditEventInput {
  userId: string;
  event: string;
  ip: string;
  userAgent: string;
  metadata?: Record<string, unknown>;
}

export interface AuditEventRecord {
  id: string;
  userId: string;
  event: string;
  ipHash: string;
  userAgentHash: string;
  timestamp: string;
  metadata: Record<string, unknown>;
}

/** Minimal contract for the append-only sink (Postgres, flat file, SIEM stream, etc.). */
export interface AuditSink {
  append(record: AuditEventRecord): Promise<void>;
}

let sequence = 0;

export class AuditTrailLogger {
  constructor(private readonly sink: AuditSink) {}

  private static hashField(value: string): string {
    return createHash("sha256").update(value).digest("hex");
  }

  private static nextId(): string {
    sequence += 1;
    return `evt_${Date.now().toString(36)}_${sequence}`;
  }

  /**
   * Records a single audit event. This method never throws on sink failure
   * in a way that blocks the caller's primary flow's return value, but it
   * does propagate errors so upstream services can alert on audit-logging
   * outages (an audit gap is itself a security event).
   */
  public async record(input: AuditEventInput): Promise<AuditEventRecord> {
    const record: AuditEventRecord = {
      id: AuditTrailLogger.nextId(),
      userId: input.userId,
      event: input.event,
      ipHash: AuditTrailLogger.hashField(input.ip),
      userAgentHash: AuditTrailLogger.hashField(input.userAgent),
      timestamp: new Date().toISOString(),
      metadata: input.metadata ?? {},
    };
    await this.sink.append(record);
    return record;
  }
}
