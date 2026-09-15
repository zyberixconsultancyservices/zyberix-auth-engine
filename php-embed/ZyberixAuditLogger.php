<?php
/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — LIGHT-EMBED ENGINE (Shared Hosting / cPanel)
 *  File:      php-embed/ZyberixAuditLogger.php
 *  Component: Immutable Audit Trail (SQLite-backed)
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 */

declare(strict_types=1);

final class ZyberixAuditLogger
{
    public function __construct(private readonly \PDO $pdo)
    {
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function record(string $userId, string $event, string $ip, string $userAgent, array $metadata = []): void
    {
        $stmt = $this->pdo->prepare('
            INSERT INTO zyberix_audit_log (id, user_id, event, ip_hash, user_agent_hash, metadata, created_at)
            VALUES (:id, :user_id, :event, :ip_hash, :ua_hash, :metadata, :created_at)
        ');

        $stmt->execute([
            'id' => 'evt_' . bin2hex(random_bytes(10)),
            'user_id' => $userId,
            'event' => $event,
            'ip_hash' => hash('sha256', $ip),
            'ua_hash' => hash('sha256', $userAgent),
            'metadata' => json_encode($metadata, JSON_THROW_ON_ERROR),
            'created_at' => gmdate('c'),
        ]);
    }
}
