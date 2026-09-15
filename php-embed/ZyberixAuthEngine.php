<?php
/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — LIGHT-EMBED ENGINE (Shared Hosting / cPanel)
 *  File:      php-embed/ZyberixAuthEngine.php
 *  Component: Core Orchestrator — Modules A (Email Reveal) & B (TOTP)
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 *
 * This is the drop-in engine used directly on shared hosting: no daemons,
 * no Redis, no Node — just PHP-FPM/Apache + SQLite (or MySQL). It implements
 * Module A (10-minute single-use email reveal-link OTP) and Module B
 * (RFC 6238 TOTP) end-to-end. Modules C/D/E (WhatsApp/Telegram, WebAuthn,
 * push) require a persistent process (websockets / webhook receivers) and
 * ship in the Microservice Engine instead — see docs/ARCHITECTURE.md.
 *
 * Zero raw secrets are ever persisted: OTPs are hashed with password_hash()
 * (Argon2id where available, bcrypt fallback on hosts without libargon2),
 * and TOTP seeds are AES-256-GCM encrypted at rest via ZyberixCryptoEngine.
 */

declare(strict_types=1);

final class ZyberixAuthEngine
{
    private \PDO $pdo;
    private ZyberixCryptoEngine $crypto;
    private ZyberixRateLimiter $rateLimiter;
    private ZyberixAuditLogger $audit;
    private ZyberixConfig $config;

    public function __construct(ZyberixConfig $config)
    {
        $this->config = $config;
        $db = new ZyberixDatabase($config->databaseDsn, $config->databaseUser, $config->databasePassword);
        $this->pdo = $db->pdo();
        $this->crypto = new ZyberixCryptoEngine($config->masterKeyBase64);
        $this->rateLimiter = new ZyberixRateLimiter($this->pdo);
        $this->audit = new ZyberixAuditLogger($this->pdo);
    }

    /** Hashing algorithm used for OTPs — Argon2id if the PHP build supports it, else bcrypt. */
    private function otpHashAlgo(): string
    {
        return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
    }

    // ------------------------------------------------------------------
    // MODULE A: Email Reveal-Link OTP
    // ------------------------------------------------------------------

    /**
     * Triggers a new email reveal-link verification.
     *
     * @return array{verificationId: string, revealUrl: string, expiresAt: string}
     */
    public function triggerEmailVerification(
        string $userId,
        string $email,
        string $actionContext,
        string $requestIp,
        string $requestUserAgent
    ): array {
        if (!$this->rateLimiter->check('ip:' . $requestIp) || !$this->rateLimiter->check('user:' . $userId)) {
            throw new ZyberixRateLimitException('Too many verification attempts. Please wait before retrying.');
        }

        $otp = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $otpHash = password_hash($otp, $this->otpHashAlgo());
        $verificationId = 'ver_' . bin2hex(random_bytes(12));
        $revealToken = bin2hex(random_bytes(32));

        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $expiresAt = $now->modify('+' . $this->config->revealLinkTtlSeconds . ' seconds');

        $stmt = $this->pdo->prepare('
            INSERT INTO zyberix_verifications
                (id, user_id, action_context, channel, secret_hash, reveal_token, status, attempts, created_at, expires_at)
            VALUES
                (:id, :user_id, :action_context, :channel, :secret_hash, :reveal_token, :status, 0, :created_at, :expires_at)
        ');
        $stmt->execute([
            'id' => $verificationId,
            'user_id' => $userId,
            'action_context' => $actionContext,
            'channel' => 'email',
            'secret_hash' => $otpHash,
            'reveal_token' => $revealToken,
            'status' => 'PENDING',
            'created_at' => $now->format('c'),
            'expires_at' => $expiresAt->format('c'),
        ]);

        // Hold the plaintext OTP only in a short-lived, encrypted, TTL-bound
        // row — separate from the Argon2id hash above — so the reveal page
        // can display it exactly once. This is the only place a recoverable
        // OTP touches storage, and it is deleted immediately on first read.
        $encryptedOtp = $this->crypto->encrypt($otp);
        $this->pdo->prepare('
            CREATE TABLE IF NOT EXISTS zyberix_pending_reveal (
                reveal_token TEXT PRIMARY KEY,
                otp_encrypted TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        ')->execute();
        $this->pdo->prepare('
            INSERT INTO zyberix_pending_reveal (reveal_token, otp_encrypted, expires_at)
            VALUES (:token, :otp, :expires_at)
        ')->execute([
            'token' => $revealToken,
            'otp' => $encryptedOtp,
            'expires_at' => $expiresAt->format('c'),
        ]);

        $revealUrl = rtrim($this->config->publicBaseUrl, '/') . '/reveal/' . $revealToken;
        $this->sendRevealEmail($email, $revealUrl, $actionContext);

        $this->audit->record($userId, 'EMAIL_REVEAL_TRIGGERED', $requestIp, $requestUserAgent, [
            'actionContext' => $actionContext,
            'verificationId' => $verificationId,
        ]);

        return [
            'verificationId' => $verificationId,
            'revealUrl' => $revealUrl,
            'expiresAt' => $expiresAt->format('c'),
        ];
    }

    /**
     * Resolves (burns) a reveal token exactly once and returns the plaintext
     * OTP for display. Throws on missing/expired/already-consumed tokens.
     *
     * @return array{otp: string}
     */
    public function resolveReveal(string $revealToken, string $requestIp, string $requestUserAgent): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM zyberix_pending_reveal WHERE reveal_token = :token');
        $stmt->execute(['token' => $revealToken]);
        $row = $stmt->fetch();

        if (!$row) {
            $this->audit->record('unknown', 'EMAIL_REVEAL_INVALID_OR_CONSUMED', $requestIp, $requestUserAgent, [
                'tokenPrefix' => substr($revealToken, 0, 8),
            ]);
            throw new ZyberixVerificationException('This reveal link is invalid or has already been used.');
        }

        // Burn immediately — single-use regardless of expiry outcome below.
        $this->pdo->prepare('DELETE FROM zyberix_pending_reveal WHERE reveal_token = :token')
            ->execute(['token' => $revealToken]);

        $expiresAt = new \DateTimeImmutable($row['expires_at']);
        if ($expiresAt < new \DateTimeImmutable('now', new \DateTimeZone('UTC'))) {
            $this->audit->record('unknown', 'EMAIL_REVEAL_EXPIRED', $requestIp, $requestUserAgent, []);
            throw new ZyberixVerificationException('This reveal link has expired.');
        }

        $otp = $this->crypto->decrypt($row['otp_encrypted']);

        $verStmt = $this->pdo->prepare('SELECT user_id, action_context FROM zyberix_verifications WHERE reveal_token = :token');
        $verStmt->execute(['token' => $revealToken]);
        $verRow = $verStmt->fetch();

        $this->audit->record($verRow['user_id'] ?? 'unknown', 'EMAIL_REVEAL_CONSUMED', $requestIp, $requestUserAgent, [
            'actionContext' => $verRow['action_context'] ?? null,
        ]);

        return ['otp' => $otp];
    }

    /**
     * Submits a code (from the reveal flow) for final verification against
     * the stored Argon2id hash. This is the authoritative check the calling
     * application should rely on — never trust the reveal-page display alone.
     */
    public function submitVerificationCode(string $verificationId, string $code, string $requestIp, string $requestUserAgent): bool
    {
        if (!$this->rateLimiter->check('verify:' . $verificationId)) {
            throw new ZyberixRateLimitException('Too many attempts on this verification.');
        }

        $stmt = $this->pdo->prepare('SELECT * FROM zyberix_verifications WHERE id = :id');
        $stmt->execute(['id' => $verificationId]);
        $row = $stmt->fetch();

        if (!$row) {
            throw new ZyberixVerificationException('Unknown verification ID.');
        }
        if ($row['status'] !== 'PENDING') {
            throw new ZyberixVerificationException('This verification has already been resolved.');
        }
        if (new \DateTimeImmutable($row['expires_at']) < new \DateTimeImmutable('now', new \DateTimeZone('UTC'))) {
            $this->markStatus($verificationId, 'EXPIRED');
            throw new ZyberixVerificationException('This verification has expired.');
        }

        $this->pdo->prepare('UPDATE zyberix_verifications SET attempts = attempts + 1 WHERE id = :id')
            ->execute(['id' => $verificationId]);

        $isValid = password_verify($code, $row['secret_hash']);

        $this->markStatus($verificationId, $isValid ? 'VERIFIED' : $row['status']);
        $this->audit->record($row['user_id'], $isValid ? 'CODE_VERIFIED' : 'CODE_REJECTED', $requestIp, $requestUserAgent, [
            'verificationId' => $verificationId,
        ]);

        return $isValid;
    }

    private function markStatus(string $verificationId, string $status): void
    {
        $stmt = $this->pdo->prepare('
            UPDATE zyberix_verifications
            SET status = :status, verified_at = CASE WHEN :status2 = \'VERIFIED\' THEN :now ELSE verified_at END
            WHERE id = :id
        ');
        $stmt->execute([
            'status' => $status,
            'status2' => $status,
            'now' => (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('c'),
            'id' => $verificationId,
        ]);
    }

    /** @return array{status: string, attempts: int, expiresAt: string} */
    public function checkStatus(string $verificationId): array
    {
        $stmt = $this->pdo->prepare('SELECT status, attempts, expires_at FROM zyberix_verifications WHERE id = :id');
        $stmt->execute(['id' => $verificationId]);
        $row = $stmt->fetch();
        if (!$row) {
            throw new ZyberixVerificationException('Unknown verification ID.');
        }
        return [
            'status' => $row['status'],
            'attempts' => (int) $row['attempts'],
            'expiresAt' => $row['expires_at'],
        ];
    }

    // ------------------------------------------------------------------
    // MODULE B: TOTP
    // ------------------------------------------------------------------

    /** @return array{secret: string, otpauthUri: string} */
    public function enrollTotp(string $userId, string $accountLabel): array
    {
        $secret = ZyberixTotp::generateSecret();
        $encryptedSecret = $this->crypto->encrypt($secret);

        $this->pdo->prepare('
            INSERT INTO zyberix_totp_secrets (user_id, secret_encrypted, created_at, confirmed)
            VALUES (:user_id, :secret, :created_at, 0)
            ON CONFLICT(user_id) DO UPDATE SET secret_encrypted = :secret2, created_at = :created_at2, confirmed = 0
        ')->execute([
            'user_id' => $userId,
            'secret' => $encryptedSecret,
            'created_at' => (new \DateTimeImmutable('now'))->format('c'),
            'secret2' => $encryptedSecret,
            'created_at2' => (new \DateTimeImmutable('now'))->format('c'),
        ]);

        return [
            'secret' => $secret,
            'otpauthUri' => ZyberixTotp::buildOtpAuthUri($secret, $accountLabel),
        ];
    }

    public function verifyTotp(string $userId, string $code, string $requestIp, string $requestUserAgent): bool
    {
        if (!$this->rateLimiter->check('totp:' . $userId)) {
            throw new ZyberixRateLimitException('Too many TOTP attempts. Please wait before retrying.');
        }

        $stmt = $this->pdo->prepare('SELECT secret_encrypted FROM zyberix_totp_secrets WHERE user_id = :user_id');
        $stmt->execute(['user_id' => $userId]);
        $row = $stmt->fetch();

        if (!$row) {
            throw new ZyberixVerificationException('No TOTP secret enrolled for this user.');
        }

        $secret = $this->crypto->decrypt($row['secret_encrypted']);
        $isValid = ZyberixTotp::verifyCode($secret, $code);

        if ($isValid) {
            $this->pdo->prepare('UPDATE zyberix_totp_secrets SET confirmed = 1 WHERE user_id = :user_id')
                ->execute(['user_id' => $userId]);
        }

        $this->audit->record($userId, $isValid ? 'TOTP_VERIFIED' : 'TOTP_REJECTED', $requestIp, $requestUserAgent, []);

        return $isValid;
    }

    // ------------------------------------------------------------------
    // Mail transport
    // ------------------------------------------------------------------

    private function sendRevealEmail(string $toEmail, string $revealUrl, string $actionContext): void
    {
        $subject = 'Your Zyberix Auth Engine verification link';
        $minutes = (int) round($this->config->revealLinkTtlSeconds / 60);
        $body = "Verify: {$actionContext}\n\n"
            . "Click to reveal your one-time code (valid {$minutes} minutes, single use):\n{$revealUrl}\n\n"
            . "If you did not request this, no action is required.";

        $headers = "From: {$this->config->mailFromAddress}\r\n"
            . "X-Powered-By: Zyberix-Auth-Engine-v1.0\r\n"
            . "Content-Type: text/plain; charset=UTF-8";

        // Uses PHP's native mail() by default (works out-of-the-box on most
        // shared hosting via the host's local MTA). If SMTP credentials are
        // configured, swap this for PHPMailer/Symfony Mailer — see
        // docs/ARCHITECTURE.md "Mail Transport" section for the drop-in.
        if (!mail($toEmail, $subject, $body, $headers)) {
            throw new \RuntimeException('ZyberixAuthEngine: failed to dispatch verification email via mail().');
        }
    }
}

final class ZyberixVerificationException extends \RuntimeException
{
}

final class ZyberixRateLimitException extends \RuntimeException
{
}
