# Zyberix Auth Engine — Architecture

## Module A: Email Reveal-Link Sequence

```mermaid
sequenceDiagram
    participant App as Client App
    participant ZAE as Zyberix Auth Engine
    participant Store as Redis (TTL)
    participant Mail as SMTP/API
    participant User as End User

    App->>ZAE: triggerVerification(userId, actionContext)
    ZAE->>ZAE: generate OTP + Argon2id hash
    ZAE->>Store: setWithTtl(revealToken, hash, 600s)
    ZAE->>Mail: send(revealUrl)
    Mail->>User: Email with reveal link
    User->>ZAE: GET /reveal/{token}
    ZAE->>Store: get + delete (burn)
    ZAE-->>User: OTP displayed once
    ZAE->>ZAE: write audit trail entry
```

## Module B: TOTP Enrollment & Verification

```mermaid
sequenceDiagram
    participant App as Client App
    participant ZAE as Zyberix Auth Engine
    participant User as End User (Authenticator App)

    App->>ZAE: enrollTotp(userId)
    ZAE-->>App: otpauth:// URI (QR)
    App-->>User: Display QR
    User->>User: Scan + generate 6-digit code
    App->>ZAE: submitCode(verificationId, code)
    ZAE->>ZAE: RFC 6238 validation (±1 step window)
    ZAE-->>App: verified: true/false
```

## Deployment Topologies

- **Shared Hosting:** Light-Embed Engine runs in-process with the host application; no background workers, no open ports beyond the existing web server.
- **Cloud VPS:** Microservice Engine + Redis + PostgreSQL via `docker-compose.yml`.
- **Kubernetes:** Same container images, deployed as a `Deployment` + `Service` + `HorizontalPodAutoscaler`, with Redis/PostgreSQL as managed services or StatefulSets. Manifests are intentionally not bundled in v1.0.0-release to avoid prescribing a specific ingress/cert-manager setup — see `docs/` for a Helm chart contribution guide.
