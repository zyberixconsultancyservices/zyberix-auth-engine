<?php
/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — LIGHT-EMBED ENGINE (Shared Hosting / cPanel)
 *  File:      php-embed/ZyberixCryptoEngine.php
 *  Component: Cryptographic Core (pure PHP, no Composer dependency)
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 *
 * AES-256-GCM encryption + HMAC-SHA256 signing using PHP's built-in OpenSSL
 * extension only. Requires PHP 8.0+ with ext-openssl (present on virtually
 * every shared hosting PHP build).
 */

declare(strict_types=1);

final class ZyberixCryptoEngine
{
    private const CIPHER = 'aes-256-gcm';
    private const IV_LENGTH = 12;
    private const TAG_LENGTH = 16;

    private string $key; // 32 raw bytes

    /**
     * @param string $base64Key 32-byte key, base64-encoded (from config / env).
     */
    public function __construct(string $base64Key)
    {
        $key = base64_decode($base64Key, true);
        if ($key === false || strlen($key) !== 32) {
            throw new \InvalidArgumentException(
                'ZyberixCryptoEngine: master key must be a base64-encoded 32-byte (256-bit) value. ' .
                'Generate one with: openssl rand -base64 32'
            );
        }
        $this->key = $key;
    }

    public static function generateKeyBase64(): string
    {
        return base64_encode(random_bytes(32));
    }

    /**
     * Encrypts a plaintext string. Returns a single portable string
     * "iv.tag.ciphertext" (all base64url), safe to store in a single DB column.
     */
    public function encrypt(string $plaintext): string
    {
        $iv = random_bytes(self::IV_LENGTH);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LENGTH
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('ZyberixCryptoEngine: encryption failed.');
        }

        return implode('.', [
            self::b64url_encode($iv),
            self::b64url_encode($tag),
            self::b64url_encode($ciphertext),
        ]);
    }

    /**
     * Decrypts a string previously produced by encrypt(). Throws if the
     * authentication tag fails to verify (tamper detection).
     */
    public function decrypt(string $envelope): string
    {
        $parts = explode('.', $envelope);
        if (count($parts) !== 3) {
            throw new \RuntimeException('ZyberixCryptoEngine: malformed cipher envelope.');
        }
        [$ivB64, $tagB64, $ctB64] = $parts;

        $iv = self::b64url_decode($ivB64);
        $tag = self::b64url_decode($tagB64);
        $ciphertext = self::b64url_decode($ctB64);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($plaintext === false) {
            throw new \RuntimeException('ZyberixCryptoEngine: decryption failed — data may have been tampered with.');
        }

        return $plaintext;
    }

    /** HMAC-SHA256 signature, base64url encoded. */
    public function sign(string $payload): string
    {
        return self::b64url_encode(hash_hmac('sha256', $payload, $this->key, true));
    }

    /** Constant-time signature verification. */
    public function verify(string $payload, string $signature): bool
    {
        $expected = $this->sign($payload);
        return hash_equals($expected, $signature);
    }

    private static function b64url_encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function b64url_decode(string $data): string
    {
        $padded = str_pad(strtr($data, '-_', '+/'), (int) (4 * ceil(strlen($data) / 4)), '=', STR_PAD_RIGHT);
        $decoded = base64_decode($padded, true);
        if ($decoded === false) {
            throw new \RuntimeException('ZyberixCryptoEngine: invalid base64url input.');
        }
        return $decoded;
    }
}
