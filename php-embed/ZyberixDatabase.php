<?php
/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — LIGHT-EMBED ENGINE (Shared Hosting / cPanel)
 *  File:      php-embed/ZyberixDatabase.php
 *  Component: Storage Layer (SQLite via PDO, zero external daemons)
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 *
 * Uses SQLite (bundled with PHP's pdo_sqlite extension on essentially all
 * shared hosting) so no separate database server is required. If a MySQL
 * DSN is supplied instead, the same schema is created there — see
 * ZyberixConfig for connection selection.
 *
 * TTL/expiry is enforced at the application layer (ZyberixAuthEngine),
 * since SQLite/MySQL have no native TTL mechanism like Redis.
 */

declare(strict_types=1);

final class ZyberixDatabase
{
    private \PDO $pdo;

    /**
     * @param string $dsn PDO DSN, e.g. "sqlite:/home/user/zyberix_data/zyberix.sqlite"
     *                     or "mysql:host=localhost;dbname=zyberix_auth;charset=utf8mb4"
     * @param string|null $username Required for MySQL, ignored for SQLite.
     * @param string|null $password Required for MySQL, ignored for SQLite.
     */
    public function __construct(string $dsn, ?string $username = null, ?string $password = null)
    {
        $this->pdo = new \PDO($dsn, $username, $password, [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
            \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
        ]);

        if (str_starts_with($dsn, 'sqlite:')) {
            $this->pdo->exec('PRAGMA journal_mode = WAL;');
            $this->pdo->exec('PRAGMA foreign_keys = ON;');
        }

        $this->migrate();
    }

    public function pdo(): \PDO
    {
        return $this->pdo;
    }

    /** Creates all required tables if they do not already exist. Safe to call on every request. */
    private function migrate(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS zyberix_verifications (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                action_context TEXT NOT NULL,
                channel TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                reveal_token TEXT UNIQUE,
                status TEXT NOT NULL DEFAULT 'PENDING',
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                verified_at TEXT
            );
        ");

        $this->pdo->exec("
            CREATE INDEX IF NOT EXISTS idx_zyberix_verifications_reveal_token
            ON zyberix_verifications (reveal_token);
        ");

        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS zyberix_totp_secrets (
                user_id TEXT PRIMARY KEY,
                secret_encrypted TEXT NOT NULL,
                created_at TEXT NOT NULL,
                confirmed INTEGER NOT NULL DEFAULT 0
            );
        ");

        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS zyberix_audit_log (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                event TEXT NOT NULL,
                ip_hash TEXT NOT NULL,
                user_agent_hash TEXT NOT NULL,
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
        ");

        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS zyberix_rate_limit (
                bucket_key TEXT PRIMARY KEY,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                window_started_at TEXT NOT NULL,
                breaker_until TEXT
            );
        ");
    }
}
