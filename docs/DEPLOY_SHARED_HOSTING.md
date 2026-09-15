# Deploying on Shared Hosting / cPanel

The Light-Embed Engine needs **only PHP 8.1+ with `ext-pdo_sqlite` and `ext-openssl`** — both are enabled by default on virtually every cPanel/PHP-FPM host. No Node.js, Redis, Docker, or SSH access is required (though SSH makes step 4 easier).

## 1. Upload the files

Your hosting account's web root is usually `public_html/`. **Only the contents of this repo's `public_html/` folder should end up inside your host's `public_html/`.** Everything else (`php-embed/`, the SQLite database, your `.env`) must live **one level above** the web root, where the public internet cannot request it directly.

```
/home/yourcpaneluser/
├── php-embed/                 <- upload here (NOT web-accessible)
├── zyberix_data/               <- create this empty folder (NOT web-accessible)
└── public_html/                <- your host's web root
    ├── index.php                (from this repo's public_html/)
    └── .htaccess                (from this repo's public_html/)
```

If your hosting control panel only gives you one web-exposed folder and you cannot place `php-embed/` outside it, at minimum add a `.htaccess` inside `php-embed/` with `Require all denied` (Apache 2.4+) to block direct web access to it.

## 2. Set environment variables

Most cPanel hosts support this under **"Setup PHP App"** or via a `.env` file loaded early. Required values (see `.env.example`):

| Variable | Example | Notes |
|---|---|---|
| `ZYBERIX_MASTER_KEY` | (output of `openssl rand -base64 32`) | 32-byte AES key, base64 |
| `ZYBERIX_DATABASE_DSN` | `sqlite:/home/yourcpaneluser/zyberix_data/zyberix.sqlite` | Absolute path, outside web root |
| `ZYBERIX_API_KEY` | (output of `openssl rand -hex 24`) | Required Bearer token for all API calls |
| `ZYBERIX_PUBLIC_BASE_URL` | `https://app.yourdomain.com` | Used to build reveal links |
| `ZYBERIX_MAIL_FROM` | `no-reply@yourdomain.com` | Must be a domain your host is authorized to send as (set up SPF/DKIM) |

If your host doesn't expose an environment-variable UI, create `php-embed/.env.local.php` (outside web root) that calls `putenv()` for each value before `ZyberixConfig::fromEnv()` runs, and require it at the top of `public_html/index.php`.

## 3. Create the data directory

```bash
mkdir -p /home/yourcpaneluser/zyberix_data
chmod 750 /home/yourcpaneluser/zyberix_data
```

The SQLite file and its schema are created automatically on first request — no manual migration step.

## 4. Verify

```bash
curl https://app.yourdomain.com/healthz
# {"status":"ok","service":"Zyberix Auth Engine","version":"1.0.0"}

curl -X POST https://app.yourdomain.com/verifications \
  -H "Authorization: Bearer $ZYBERIX_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"userId":"user_123","email":"you@yourdomain.com","actionContext":"HIGH_RISK_ACTION:test"}'
```

You should receive an email with a reveal link within a minute (subject to your host's mail queue).

## 5. Production checklist before going live

- [ ] `ZYBERIX_MASTER_KEY` and `ZYBERIX_API_KEY` are generated per-environment and stored in a secrets manager or the host's env-var UI — never committed to git.
- [ ] `php-embed/` and `zyberix_data/` are confirmed **not** reachable over HTTP (test: `curl https://app.yourdomain.com/../php-embed/ZyberixAuthEngine.php` should 403/404).
- [ ] HTTPS is enforced (the bundled `.htaccess` does this, but confirm your host's cert is valid).
- [ ] SPF/DKIM are configured for `ZYBERIX_MAIL_FROM`'s domain so verification emails don't land in spam.
- [ ] `zyberix_data/zyberix.sqlite` is included in your regular backup routine.
- [ ] If `ext-openssl`'s Argon2id support (`PASSWORD_ARGON2ID`) isn't available on your host's PHP build, the engine automatically falls back to bcrypt — check `php -m | grep -i argon` if you want to confirm which one is active.
- [ ] Load-test the `/verifications` endpoint at your expected concurrency; SQLite handles moderate write volume well but a high-traffic deployment should migrate `ZYBERIX_DATABASE_DSN` to a MySQL DSN (schema is created identically on both).

## When to graduate to the Microservice Engine

The Light-Embed Engine covers Module A (email reveal-link) and Module B (TOTP) completely. If you need Module C (WhatsApp/Telegram), Module D (WebAuthn/Passkeys), or Module E (real-time push), those require a long-running process for websockets/webhook receivers that shared hosting's request-per-process PHP model doesn't support well — deploy the Microservice Engine (`docker-compose.yml`) for those, optionally alongside the Light-Embed Engine for Modules A/B.
