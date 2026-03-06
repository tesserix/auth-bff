# Auth BFF

Backend-for-Frontend authentication service for the Tesserix platform. Handles OIDC authentication flows, session management, MFA (TOTP and Passkeys), and CSRF protection.

## Features

- **OIDC Authentication**: Login/callback/logout via Google Identity Platform (GIP)
- **Session Management**: Secure cookie-based sessions with refresh token rotation
- **CSRF Protection**: Token-based CSRF prevention
- **Rate Limiting**: Request rate limiting per client
- **MFA - TOTP**: Time-based one-time password setup and verification
- **MFA - Passkeys**: WebAuthn passkey registration and authentication
- **Multi-Product App Registry**: Configurable per-product authentication settings
- **Service-to-Service**: Internal token verification and session exchange endpoints

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.26 |
| Framework | Gin |
| OIDC | coreos/go-oidc v3 |
| OAuth2 | golang.org/x/oauth2 |
| Shared Lib | tesserix/go-shared v1.3 |
| Deployment | Cloud Run |

## API Endpoints

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness probe |

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/login` | Initiate OIDC login flow |
| GET | `/auth/callback` | OIDC callback handler |
| POST | `/auth/logout` | Logout and clear session |
| GET | `/auth/session` | Get current session info |
| POST | `/auth/refresh` | Refresh access token |
| GET | `/auth/csrf-token` | Get CSRF token |

### MFA - TOTP

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/mfa/totp/setup` | Begin TOTP setup (requires session) |
| POST | `/auth/mfa/totp/verify-setup` | Complete TOTP setup (requires session) |
| POST | `/auth/mfa/totp/verify` | Verify TOTP code |
| POST | `/auth/mfa/totp/disable` | Disable TOTP (requires session) |

### MFA - Passkeys (WebAuthn)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/mfa/passkey/register-begin` | Begin passkey registration (requires session) |
| POST | `/auth/mfa/passkey/register-finish` | Complete passkey registration (requires session) |
| GET | `/auth/mfa/passkeys` | List registered passkeys (requires session) |
| DELETE | `/auth/mfa/passkeys/:id` | Delete passkey (requires session) |

### Internal (Service-to-Service)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/internal/verify-token` | Verify a token |
| POST | `/internal/session-exchange` | Session exchange |

## Project Structure

```
auth-bff/
├── cmd/auth-bff/
│   └── main.go
├── internal/
│   ├── appregistry/     # Multi-product app registry
│   ├── clients/         # External service clients (tenant, verification)
│   ├── config/          # Configuration and product settings
│   ├── crypto/          # AES encryption and HMAC utilities
│   ├── events/          # Event publishing
│   ├── gip/             # Google Identity Platform client
│   ├── handlers/        # HTTP handlers (auth, mfa, health, internal)
│   ├── middleware/       # CSRF, rate limiting, session middleware
│   └── session/         # Session management (cookies, ephemeral sessions)
├── products.yaml        # Per-product auth configuration
└── Dockerfile
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 8080 | HTTP port |
| `ENVIRONMENT` | development | Environment name |
| `OIDC_ISSUER_URL` | | OIDC provider issuer URL |
| `OIDC_CLIENT_ID` | | OIDC client ID |
| `OIDC_CLIENT_SECRET` | | OIDC client secret |
| `SESSION_SECRET` | | Session encryption secret |
| `CSRF_SECRET` | | CSRF token secret |
| `ALLOWED_ORIGINS` | | Comma-separated allowed CORS origins |
| `GIP_API_KEY` | | Google Identity Platform API key |
| `GIP_PROJECT_ID` | | GCP project ID for GIP |

## Running Locally

```bash
go run cmd/auth-bff/main.go
```

## License

Proprietary - Tesserix
