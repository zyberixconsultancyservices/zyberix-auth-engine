<?php
/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — LIGHT-EMBED ENGINE (Shared Hosting / cPanel)
 *  File:      php-embed/ZyberixTotp.php
 *  Component: Module B — RFC 6238 TOTP (pure PHP, no Composer dependency)
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 */

declare(strict_types=1);

final class ZyberixTotp
{
    private const PERIOD_SECONDS = 30;
    private const DIGITS = 6;
    private const ALGO = 'sha1'; // RFC 6238 default; matches Google/Microsoft Authenticator

    /** Generates a random Base32 secret suitable for authenticator apps. */
    public static function generateSecret(int $bytes = 20): string
    {
        return self::base32Encode(random_bytes($bytes));
    }

    /** Builds an otpauth:// URI for QR-code enrollment. */
    public static function buildOtpAuthUri(string $secretBase32, string $accountLabel, string $issuer = 'Zyberix Auth Engine'): string
    {
        $label = rawurlencode($issuer) . ':' . rawurlencode($accountLabel);
        $query = http_build_query([
            'secret' => $secretBase32,
            'issuer' => $issuer,
            'algorithm' => strtoupper(self::ALGO),
            'digits' => self::DIGITS,
            'period' => self::PERIOD_SECONDS,
        ]);
        return "otpauth://totp/{$label}?{$query}";
    }

    /** Generates the current TOTP code for a given secret and timestamp. */
    public static function generateCode(string $secretBase32, ?int $timestamp = null): string
    {
        $timestamp ??= time();
        $counter = intdiv($timestamp, self::PERIOD_SECONDS);
        return self::hotp(self::base32Decode($secretBase32), $counter);
    }

    /**
     * Verifies a user-submitted code, allowing a ±1 step drift window
     * (i.e., ±30 seconds) to tolerate minor clock skew, per RFC 6238 guidance.
     */
    public static function verifyCode(string $secretBase32, string $submittedCode, ?int $timestamp = null): bool
    {
        $timestamp ??= time();
        $submittedCode = preg_replace('/\s+/', '', $submittedCode) ?? '';

        for ($drift = -1; $drift <= 1; $drift++) {
            $candidateTime = $timestamp + ($drift * self::PERIOD_SECONDS);
            $expected = self::generateCode($secretBase32, $candidateTime);
            if (hash_equals($expected, $submittedCode)) {
                return true;
            }
        }
        return false;
    }

    private static function hotp(string $secretRaw, int $counter): string
    {
        $counterBytes = pack('N*', 0) . pack('N*', $counter); // 8-byte big-endian counter
        $hash = hash_hmac(self::ALGO, $counterBytes, $secretRaw, true);

        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $binary = ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF);

        $otp = $binary % (10 ** self::DIGITS);
        return str_pad((string) $otp, self::DIGITS, '0', STR_PAD_LEFT);
    }

    private static function base32Encode(string $data): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $bits = '';
        foreach (str_split($data) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        $output = '';
        foreach (str_split($bits, 5) as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $output .= $alphabet[bindec($chunk)];
        }
        return $output;
    }

    private static function base32Decode(string $data): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $data = strtoupper(rtrim($data, '='));
        $bits = '';
        foreach (str_split($data) as $char) {
            $pos = strpos($alphabet, $char);
            if ($pos === false) {
                continue;
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        $bytes = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $bytes .= chr(bindec($byte));
            }
        }
        return $bytes;
    }
}
