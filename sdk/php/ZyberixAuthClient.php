<?php

/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — OFFICIAL PHP SDK
 *  File:      sdk/php/ZyberixAuthClient.php
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 *
 * Zero-dependency (cURL-based) PHP client, built for drop-in use on shared
 * hosting / cPanel environments where Composer packages may be restricted.
 *
 * Usage:
 *   require_once 'ZyberixAuthClient.php';
 *   $zyberix = new ZyberixAuthClient(['api_key' => getenv('ZYBERIX_API_KEY')]);
 *   $result = $zyberix->triggerVerification('user_123', 'HIGH_RISK_ACTION');
 *   $status = $zyberix->checkStatus($result['verificationId']);
 */

declare(strict_types=1);

final class ZyberixApiException extends \RuntimeException
{
    /** @var int */
    public $statusCode;

    /** @var mixed */
    public $responseBody;

    public function __construct(string $message, int $statusCode, $responseBody)
    {
        parent::__construct($message);
        $this->statusCode = $statusCode;
        $this->responseBody = $responseBody;
    }
}

final class ZyberixAuthClient
{
    private string $apiKey;
    private string $baseUrl;
    private int $timeoutSeconds;

    /**
     * @param array{api_key: string, base_url?: string, timeout_seconds?: int} $config
     */
    public function __construct(array $config)
    {
        if (empty($config['api_key'])) {
            throw new \InvalidArgumentException("ZyberixAuthClient: 'api_key' is required.");
        }

        $this->apiKey = $config['api_key'];
        $this->baseUrl = rtrim($config['base_url'] ?? 'https://engine.zyberix.io/api/v1', '/');
        $this->timeoutSeconds = $config['timeout_seconds'] ?? 8;
    }

    /**
     * Triggers a two-factor action verification for a user.
     *
     * @param string $userId
     * @param string $actionContext e.g. 'HIGH_RISK_ACTION:password_reset'
     * @param string|null $channel  One of: email, totp, whatsapp, telegram, webauthn, push
     * @return array{verificationId: string, channel: string, expiresAt: string}
     */
    public function triggerVerification(string $userId, string $actionContext, ?string $channel = null): array
    {
        $payload = ['userId' => $userId, 'actionContext' => $actionContext];
        if ($channel !== null) {
            $payload['channel'] = $channel;
        }

        return $this->request('POST', '/verifications', $payload);
    }

    /**
     * Fetches the current status of a verification request.
     *
     * @return array{verified: bool, status: string, verifiedAt: ?string}
     */
    public function checkStatus(string $verificationId): array
    {
        return $this->request('GET', '/verifications/' . rawurlencode($verificationId));
    }

    /**
     * Submits a user-provided verification code (TOTP or reveal-link OTP).
     */
    public function submitCode(string $verificationId, string $code): array
    {
        return $this->request(
            'POST',
            '/verifications/' . rawurlencode($verificationId) . '/submit',
            ['code' => $code]
        );
    }

    /**
     * Enrolls a new TOTP secret for a user and returns an otpauth:// URI
     * suitable for rendering as a QR code.
     */
    public function enrollTotp(string $userId): array
    {
        return $this->request('POST', '/totp/enroll', ['userId' => $userId]);
    }

    /**
     * @param array<string, mixed>|null $body
     * @return array<string, mixed>
     */
    private function request(string $method, string $path, ?array $body = null): array
    {
        $url = $this->baseUrl . $path;
        $ch = curl_init($url);

        $headers = [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $this->apiKey,
            'X-Powered-By: Zyberix-Auth-Engine-v1.0',
        ];

        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body, JSON_THROW_ON_ERROR));
        }

        $responseRaw = curl_exec($ch);

        if ($responseRaw === false) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new \RuntimeException("ZyberixAuthClient transport error: {$error}");
        }

        $statusCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $decoded = json_decode($responseRaw, true);

        if ($statusCode < 200 || $statusCode >= 300) {
            throw new ZyberixApiException(
                "Zyberix Auth Engine request failed with status {$statusCode}",
                $statusCode,
                $decoded
            );
        }

        return is_array($decoded) ? $decoded : [];
    }
}
