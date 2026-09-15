# Zyberix Auth Engine — Threat Model

Scope: the verification service itself (Modules A–E), its token store, and its audit trail. Out of scope: the host application's own authentication/session layer, which Zyberix Auth Engine assumes is already in place — this product verifies *actions*, not primary login.

## STRIDE Summary

| Category | Risk | Control |
|---|---|---|
| Spoofing | Forged webhook callbacks (WhatsApp/Telegram) | HMAC-SHA256 signature, constant-time verify |
| Tampering | Modified audit records | Append-only sink, sequential IDs, hashed fields |
| Repudiation | User denies requesting/approving an action | Immutable audit trail with timestamp + hashed IP/UA per event |
| Information Disclosure | OTP or TOTP seed leaked from storage | Argon2id one-way hashing; AES-256-GCM envelope encryption for any at-rest secret material |
| Denial of Service | Flood of verification triggers | Sliding-window rate limiter + circuit breaker with cooldown |
| Elevation of Privilege | Reveal-link token guessed or replayed | 256-bit CSPRNG tokens, single-use burn semantics, 10-minute TTL |

## Residual Risks & Operator Responsibilities

- **Email account compromise:** if the user's inbox is compromised, Module A alone is insufficient for the highest-risk actions — pair with Module B/D for step-up assurance on the most sensitive operations.
- **Key management:** `ZYBERIX_MASTER_KEY` must be provisioned via a secrets manager (Vault, AWS Secrets Manager, etc.) in production, not a plain `.env` file on disk.
- **Clock drift:** TOTP validation windows assume NTP-synced server time; operators should monitor drift alerts.
