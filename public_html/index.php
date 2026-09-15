<?php
/**
 * ============================================================================
 *  ZYBERIX AUTH ENGINE — LIGHT-EMBED ENGINE (Shared Hosting / cPanel)
 *  File:      public_html/index.php
 *  Component: HTTP Front Controller / REST API Router
 *  Maintainer: Zyberix Consultancy Services
 *  License:   Apache-2.0 (c) Zyberix Consultancy Services
 *  Signature: X-Powered-By: Zyberix-Auth-Engine-v1.0
 * ============================================================================
 *
 * DEPLOYMENT (shared hosting / cPanel):
 *   1. Upload the whole repository so that `public_html/` (or your hosting
 *      account's web root, e.g. `public_html/`) is the ONLY web-accessible
 *      folder. Everything else (`php-embed/`, config, database file) must
 *      live OUTSIDE the web root so it cannot be downloaded directly.
 *
 *        /home/youruser/
 *          php-embed/              <- not web accessible
 *          zyberix_data/           <- SQLite DB lives here, not web accessible
 *          public_html/            <- web root, only this is exposed
 *            index.php             <- this file
 *            .htaccess
 *
 *   2. Set environment variables in cPanel ("Setup Node.js/PHP App" > Environment
 *      Variables, or a .env loaded by your host) — see .env.example:
 *      ZYBERIX_MASTER_KEY, ZYBERIX_DATABASE_DSN, ZYBERIX_API_KEY, ZYBERIX_PUBLIC_BASE_URL,
 *      ZYBERIX_MAIL_FROM
 *
 *   3. This single file handles every route below — no build step required.
 *
 * ROUTES:
 *   POST /verifications                       trigger a verification
 *   GET  /verifications/{id}                   check status
 *   POST /verifications/{id}/submit            submit a code
 *   GET  /reveal/{token}                        resolve + display OTP once (HTML page)
 *   POST /totp/enroll                           enroll a new TOTP secret
 *   POST /totp/verify                           verify a TOTP code
 *   GET  /healthz                               liveness check (no auth required)
 */

declare(strict_types=1);

require_once __DIR__ . '/../php-embed/autoload.php';

header('X-Powered-By: Zyberix-Auth-Engine-v1.0');
header('Content-Type: application/json; charset=utf-8');

function zyberix_json_input(): array
{
    $raw = file_get_contents('php://input') ?: '';
    if ($raw === '') {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function zyberix_respond(int $status, array $body): never
{
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_SLASHES);
    exit;
}

function zyberix_client_ip(): string
{
    return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function zyberix_user_agent(): string
{
    return $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
}

try {
    $config = ZyberixConfig::fromEnv();
} catch (\Throwable $e) {
    // Fail closed with a generic message — never leak config details publicly.
    error_log('[Zyberix Auth Engine] Configuration error: ' . $e->getMessage());
    zyberix_respond(500, ['error' => 'Server misconfiguration. Check application logs.']);
}

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = rtrim($path, '/') ?: '/';

// --- Health check: no auth required, useful for uptime monitors -----------
if ($method === 'GET' && $path === '/healthz') {
    zyberix_respond(200, ['status' => 'ok', 'service' => 'Zyberix Auth Engine', 'version' => '1.0.0']);
}

// --- Reveal page: browser-visited link, no API key required (the 256-bit --
// --- token in the URL itself is the credential) ----------------------------
if ($method === 'GET' && preg_match('#^/reveal/([A-Za-z0-9]+)$#', $path, $m)) {
    header('Content-Type: text/html; charset=utf-8');
    $engine = new ZyberixAuthEngine($config);
    try {
        $result = $engine->resolveReveal($m[1], zyberix_client_ip(), zyberix_user_agent());
        http_response_code(200);
        echo '<!doctype html><html><head><meta charset="utf-8"><title>Zyberix Auth Engine</title>'
            . '<meta name="robots" content="noindex"></head><body style="font-family:sans-serif;max-width:420px;margin:80px auto;text-align:center;">'
            . '<p style="letter-spacing:.08em;text-transform:uppercase;color:#64748b;font-size:12px;">Zyberix Auth Engine</p>'
            . '<h2>Your verification code</h2>'
            . '<div style="font-size:32px;font-weight:700;letter-spacing:.15em;padding:16px;background:#f1f5f9;border-radius:12px;">'
            . htmlspecialchars($result['otp'], ENT_QUOTES) . '</div>'
            . '<p style="color:#94a3b8;font-size:13px;margin-top:24px;">This code will not be shown again. Enter it in the application that requested verification.</p>'
            . '</body></html>';
    } catch (ZyberixVerificationException $e) {
        http_response_code(410);
        echo '<!doctype html><html><body style="font-family:sans-serif;max-width:420px;margin:80px auto;text-align:center;">'
            . '<h2>Link expired or already used</h2><p>' . htmlspecialchars($e->getMessage(), ENT_QUOTES) . '</p></body></html>';
    }
    exit;
}

// --- Every route below requires: Authorization: Bearer <ZYBERIX_API_KEY> --
$authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$providedKey = str_starts_with($authHeader, 'Bearer ') ? substr($authHeader, 7) : '';

if (!hash_equals($config->apiKey, $providedKey)) {
    zyberix_respond(401, ['error' => 'Missing or invalid API key.']);
}

$engine = new ZyberixAuthEngine($config);
$ip = zyberix_client_ip();
$ua = zyberix_user_agent();

try {
    // POST /verifications
    if ($method === 'POST' && $path === '/verifications') {
        $input = zyberix_json_input();
        foreach (['userId', 'email', 'actionContext'] as $field) {
            if (empty($input[$field])) {
                zyberix_respond(422, ['error' => "Field '{$field}' is required."]);
            }
        }
        $result = $engine->triggerEmailVerification($input['userId'], $input['email'], $input['actionContext'], $ip, $ua);
        zyberix_respond(201, $result);
    }

    // GET /verifications/{id}
    if ($method === 'GET' && preg_match('#^/verifications/([A-Za-z0-9_]+)$#', $path, $m)) {
        zyberix_respond(200, $engine->checkStatus($m[1]));
    }

    // POST /verifications/{id}/submit
    if ($method === 'POST' && preg_match('#^/verifications/([A-Za-z0-9_]+)/submit$#', $path, $m)) {
        $input = zyberix_json_input();
        if (empty($input['code'])) {
            zyberix_respond(422, ['error' => "Field 'code' is required."]);
        }
        $verified = $engine->submitVerificationCode($m[1], (string) $input['code'], $ip, $ua);
        zyberix_respond(200, ['verified' => $verified]);
    }

    // POST /totp/enroll
    if ($method === 'POST' && $path === '/totp/enroll') {
        $input = zyberix_json_input();
        if (empty($input['userId'])) {
            zyberix_respond(422, ['error' => "Field 'userId' is required."]);
        }
        $result = $engine->enrollTotp($input['userId'], $input['accountLabel'] ?? $input['userId']);
        zyberix_respond(201, $result);
    }

    // POST /totp/verify
    if ($method === 'POST' && $path === '/totp/verify') {
        $input = zyberix_json_input();
        foreach (['userId', 'code'] as $field) {
            if (empty($input[$field])) {
                zyberix_respond(422, ['error' => "Field '{$field}' is required."]);
            }
        }
        $verified = $engine->verifyTotp($input['userId'], (string) $input['code'], $ip, $ua);
        zyberix_respond(200, ['verified' => $verified]);
    }

    zyberix_respond(404, ['error' => 'Route not found.']);
} catch (ZyberixRateLimitException $e) {
    zyberix_respond(429, ['error' => $e->getMessage()]);
} catch (ZyberixVerificationException $e) {
    zyberix_respond(400, ['error' => $e->getMessage()]);
} catch (\Throwable $e) {
    error_log('[Zyberix Auth Engine] Unhandled error: ' . $e->getMessage());
    zyberix_respond(500, ['error' => 'Internal server error.']);
}
