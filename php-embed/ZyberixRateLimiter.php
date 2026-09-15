<?php
/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — LIGHT-EMBED ENGINE (Shared Hosting / cPanel)
 *  File:      php-embed/ZyberixRateLimiter.php
 *  Component: Sliding-Window Throttler & Circuit Breaker (SQLite-backed)
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 */

declare(strict_types=1);

final class ZyberixRateLimiter
{
    public function __construct(
        private readonly \PDO $pdo,
        private readonly int $windowSeconds = 60,
        private readonly int $maxRequests = 10,
        private readonly int $breakerThreshold = 20,
        private readonly int $cooldownSeconds = 900
    ) {
    }

    /**
     * Checks and records an attempt for the given bucket key (e.g. "ip:1.2.3.4"
     * or "user:abc123"). Returns true if the request is allowed.
     */
    public function check(string $bucketKey): bool
    {
        $now = time();

        $stmt = $this->pdo->prepare('SELECT * FROM zyberix_rate_limit WHERE bucket_key = :key');
        $stmt->execute(['key' => $bucketKey]);
        $row = $stmt->fetch();

        if ($row && $row['breaker_until'] !== null && (int) $row['breaker_until'] > $now) {
            return false; // Circuit breaker active — hard lockout.
        }

        if (!$row) {
            $this->pdo->prepare('
                INSERT INTO zyberix_rate_limit (bucket_key, attempt_count, window_started_at, breaker_until)
                VALUES (:key, 1, :now, NULL)
            ')->execute(['key' => $bucketKey, 'now' => (string) $now]);
            return true;
        }

        $windowStarted = (int) $row['window_started_at'];
        $windowExpired = ($now - $windowStarted) >= $this->windowSeconds;

        if ($windowExpired || ($row['breaker_until'] !== null && (int) $row['breaker_until'] <= $now)) {
            $this->pdo->prepare('
                UPDATE zyberix_rate_limit
                SET attempt_count = 1, window_started_at = :now, breaker_until = NULL
                WHERE bucket_key = :key
            ')->execute(['key' => $bucketKey, 'now' => (string) $now]);
            return true;
        }

        $newCount = (int) $row['attempt_count'] + 1;

        if ($newCount >= $this->breakerThreshold) {
            $this->pdo->prepare('
                UPDATE zyberix_rate_limit
                SET attempt_count = :count, breaker_until = :until
                WHERE bucket_key = :key
            ')->execute([
                'count' => $newCount,
                'until' => (string) ($now + $this->cooldownSeconds),
                'key' => $bucketKey,
            ]);
            return false;
        }

        if ($newCount > $this->maxRequests) {
            $this->pdo->prepare('
                UPDATE zyberix_rate_limit SET attempt_count = :count WHERE bucket_key = :key
            ')->execute(['count' => $newCount, 'key' => $bucketKey]);
            return false;
        }

        $this->pdo->prepare('
            UPDATE zyberix_rate_limit SET attempt_count = :count WHERE bucket_key = :key
        ')->execute(['count' => $newCount, 'key' => $bucketKey]);
        return true;
    }
}
