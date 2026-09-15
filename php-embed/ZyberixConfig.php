<?php
/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — LIGHT-EMBED ENGINE (Shared Hosting / cPanel)
 *  File:      php-embed/ZyberixConfig.php
 *  Component: Configuration Value Object
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 */

declare(strict_types=1);

final class ZyberixConfig
{
    public function __construct(
        /** Base64-encoded 32-byte AES key. Generate with: openssl rand -base64 32 */
        public readonly string $masterKeyBase64,
        /** PDO DSN. Default recommendation: sqlite:/absolute/path/outside/webroot/zyberix.sqlite */
        public readonly string $databaseDsn,
        public readonly ?string $databaseUser = null,
        public readonly ?string $databasePassword = null,
        /** Public URL your app is served on, e.g. https://app.example.com (no trailing slash needed). */
        public readonly string $publicBaseUrl = 'https://localhost',
        /** "From" address used on outbound verification emails. */
        public readonly string $mailFromAddress = 'no-reply@example.com',
        /** Reveal-link lifetime in seconds. Product default: 600 (10 minutes). */
        public readonly int $revealLinkTtlSeconds = 600,
        /** Shared-secret API key required on incoming requests (Authorization: Bearer <key>). */
        public readonly string $apiKey = ''
    ) {
    }

    /** Loads configuration from environment variables (recommended for production). */
    public static function fromEnv(): self
    {
        $required = static function (string $name): string {
            $value = getenv($name);
            if ($value === false || $value === '') {
                throw new \RuntimeException("ZyberixConfig: required environment variable {$name} is not set.");
            }
            return $value;
        };

        return new self(
            masterKeyBase64: $required('ZYBERIX_MASTER_KEY'),
            databaseDsn: $required('ZYBERIX_DATABASE_DSN'),
            databaseUser: getenv('ZYBERIX_DATABASE_USER') ?: null,
            databasePassword: getenv('ZYBERIX_DATABASE_PASSWORD') ?: null,
            publicBaseUrl: getenv('ZYBERIX_PUBLIC_BASE_URL') ?: 'https://localhost',
            mailFromAddress: getenv('ZYBERIX_MAIL_FROM') ?: 'no-reply@example.com',
            revealLinkTtlSeconds: (int) (getenv('ZYBERIX_REVEAL_TTL_SECONDS') ?: 600),
            apiKey: $required('ZYBERIX_API_KEY'),
        );
    }
}
