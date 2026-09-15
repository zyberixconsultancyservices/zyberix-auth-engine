<?php
/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — LIGHT-EMBED ENGINE (Shared Hosting / cPanel)
 *  File:      php-embed/autoload.php
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 * ============================================================================
 *
 * Zero-dependency class loader. No Composer required — just:
 *   require_once __DIR__ . '/php-embed/autoload.php';
 */

declare(strict_types=1);

spl_autoload_register(function (string $class): void {
    $knownClasses = [
        'ZyberixCryptoEngine',
        'ZyberixDatabase',
        'ZyberixTotp',
        'ZyberixRateLimiter',
        'ZyberixAuditLogger',
        'ZyberixAuthEngine',
        'ZyberixConfig',
        'ZyberixVerificationException',
        'ZyberixRateLimitException',
    ];

    if (in_array($class, $knownClasses, true)) {
        $file = __DIR__ . '/' . $class . '.php';
        if (is_file($file)) {
            require_once $file;
        }
    }
});
