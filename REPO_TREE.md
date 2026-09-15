# Zyberix Auth Engine — Repository Layout

```
zyberix-auth-engine/
├── README.md
├── LICENSE
├── docker-compose.yml
├── package.json
├── tsconfig.json
├── composer.json
├── .env.example
│
├── src/                                # Microservice Engine (Node.js / TypeScript)
│   ├── Security/
│   │   ├── ZyberixCryptoEngine.ts      # AES-256-GCM, key rotation, HMAC
│   │   └── ArgonHasher.ts              # Argon2id secret hashing
│   ├── Engine/
│   │   ├── EmailRevealProvider.ts      # 10-min expiring reveal-link OTP module
│   │   ├── TotpProvider.ts             # RFC 6238 TOTP engine
│   │   ├── MessagingWebhookProvider.ts # WhatsApp / Telegram dispatch
│   │   ├── WebAuthnProvider.ts         # Passkey / hardware key verification
│   │   └── PushApprovalGateway.ts      # WebSocket push + time-locked QR
│   ├── Repository/
│   │   ├── RedisTokenStore.ts          # Ephemeral TTL-based token storage
│   │   └── AuditTrailLogger.ts         # Immutable SHA-256 hashed audit log
│   ├── Utils/
│   │   └── RateLimiter.ts              # Sliding-window throttler
│   ├── routes/
│   │   └── verification.routes.ts
│   └── server.ts
│
├── php-embed/                          # Light-Embed Engine (Shared Hosting / cPanel) — keep OUTSIDE web root
│   ├── ZyberixAuthEngine.php           # Orchestrator: Modules A (email reveal) & B (TOTP)
│   ├── ZyberixCryptoEngine.php         # AES-256-GCM + HMAC (pure PHP/OpenSSL, no Composer)
│   ├── ZyberixDatabase.php             # SQLite/MySQL schema + PDO wrapper, auto-migrates
│   ├── ZyberixTotp.php                 # RFC 6238 TOTP, pure PHP (no Composer dependency)
│   ├── ZyberixRateLimiter.php          # Sliding-window throttler + circuit breaker
│   ├── ZyberixAuditLogger.php          # Immutable, SHA-256-hashed audit trail
│   ├── ZyberixConfig.php               # Env-driven configuration value object
│   └── autoload.php                    # Zero-dependency class loader
│
├── public_html/                        # Web root — the ONLY folder exposed to the internet
│   ├── index.php                       # REST API front controller / router
│   └── .htaccess                       # HTTPS enforcement, security headers, dotfile blocking
│
├── sdk/
│   ├── php/ZyberixAuthClient.php
│   ├── node/ZyberixAuthClient.js
│   ├── python/zyberix_auth_client.py
│   └── go/zyberix_auth_client.go
│
├── docker/
│   ├── Dockerfile.node
│   └── Dockerfile.php-fpm
│
├── config/
│   └── zyberix.config.example.json
│
├── tests/
│   ├── crypto.test.ts
│   └── totp.test.ts
│
└── docs/
    ├── ARCHITECTURE.md
    └── THREAT_MODEL.md
```
