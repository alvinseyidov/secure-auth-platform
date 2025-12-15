# Secure Authentication Platform

A security-focused authentication platform built with Django, designed to demonstrate real-world authentication, identity, and authorization security practices.

This project focuses on **how authentication systems fail** and how to build them **correctly** using modern cryptography and defensive techniques.

---

## What This Project Demonstrates

- Secure password storage (Argon2 / PBKDF2)
- Token-based authentication (JWT access & refresh tokens)
- Token rotation and revocation
- Brute-force protection and rate limiting
- Secure password reset flows
- Authentication audit logging
- OWASP Top 10 authentication risks

---

## Security Topics Covered

- Password hashing (Argon2, PBKDF2)
- Salting and password policies
- JWT signing and expiration
- Refresh token rotation
- Session vs token authentication
- Account lockout and rate limiting
- Authentication event auditing

---

## Core Features

- Secure user registration and login
- JWT-based authentication
- Refresh token rotation
- Login rate limiting
- Password reset with time-bound tokens
- Optional MFA (TOTP)
- Authentication audit logs
- Secure cookie configuration

---

## Why This Project Exists

Authentication is one of the most common failure points in web applications.
This project demonstrates **how authentication should be designed**, not just how to make it work.

---

## Intended Audience

- Security Engineers
- Backend Developers
- Application Security (AppSec)
- Anyone designing authentication systems

---

## Disclaimer

This project is for educational and defensive security purposes only.

---

## Getting Started

### Prerequisites

- Python 3.11+

### Setup

1. Create and activate a virtual environment:

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run migrations:

```bash
python manage.py migrate
```

4. Create a superuser:

```bash
python manage.py createsuperuser
```

5. Run the development server:

```bash
python manage.py runserver
```

6. Access the admin panel at http://127.0.0.1:8000/admin/

### Environment Variables (Optional)

For production, set these environment variables:

- `SECRET_KEY` - Django secret key
- `DEBUG` - Set to `False` in production
- `ALLOWED_HOSTS` - Comma-separated list of allowed hosts

---

## Security Baseline (Step 2)

### Cookie Security
- `SESSION_COOKIE_SECURE` / `CSRF_COOKIE_SECURE` — HTTPS-only in production
- `SESSION_COOKIE_HTTPONLY` / `CSRF_COOKIE_HTTPONLY` — Prevents JavaScript access (XSS mitigation)
- `SameSite=Lax` — Balances CSRF protection with OAuth/redirect usability

### HTTP Headers
- `X-Frame-Options: DENY` — Clickjacking protection
- `X-Content-Type-Options: nosniff` — Prevents MIME type sniffing
- `Referrer-Policy: same-origin` — Limits referrer leakage
- `SECURE_PROXY_SSL_HEADER` — Trust X-Forwarded-Proto from reverse proxy

### Password Policy
- Minimum 12 characters
- Blocks common passwords (CommonPasswordValidator)
- Blocks numeric-only passwords
- Blocks passwords similar to user attributes

### Password Hashing
- Argon2 as primary (memory-hard, GPU/ASIC resistant)
- PBKDF2 as fallback
- Requires `argon2-cffi` package

### Notes
- `SECURE_BROWSER_XSS_FILTER` is deprecated in Django 4+; modern browsers ignore X-XSS-Protection
- Use Content-Security-Policy (CSP) for XSS protection instead (future step)

---

## Security – Step 3: Authentication & Brute-Force Protection

### Why Brute-Force Protection Matters
Attackers use automated tools to try thousands of password combinations per second. Without rate limiting:
- Weak passwords can be cracked quickly
- Credential stuffing attacks (using leaked passwords from other sites) become trivial
- Even strong passwords are vulnerable given enough time

Our implementation locks accounts temporarily after 5 failed attempts (configurable), tracked per email and per IP address.

### Why Error Messages Are Generic
Authentication endpoints return "Invalid credentials" for all failures:
- Wrong password
- Non-existent user
- Inactive account

This prevents **user enumeration attacks** where attackers probe which emails have accounts. Different error messages like "User not found" vs "Wrong password" leak information attackers can exploit.

### Why Audit Logging Is Important
The `AuthenticationEvent` model records:
- Successful logins (for access tracking)
- Failed attempts (for attack detection)
- Account lockouts (for incident response)

Audit logs are **immutable** (no edit/delete in admin except for GDPR purges). This ensures forensic integrity during security investigations.

### Configuration
Environment variables for brute-force protection:
- `AUTH_MAX_ATTEMPTS` — Failed attempts before lockout (default: 5)
- `AUTH_LOCKOUT_DURATION` — Lockout duration in seconds (default: 900 = 15 min)
- `AUTH_ATTEMPT_WINDOW` — Time window for counting attempts (default: 900 = 15 min)

---

## Security – Step 4: JWT Authentication

### Token Architecture
We use a two-token system:
- **Access Token** (10 min) — Short-lived, used for API requests
- **Refresh Token** (7 days) — Long-lived, used only to get new access tokens

Short access token lifetime limits the damage window if a token is stolen. Attackers have minutes, not days.

### Why HS256?
We use HMAC-SHA256 (symmetric) signing with Django's `SECRET_KEY`:
- Simple key management for single-service deployments
- Fast signature generation and verification
- For microservices, consider RS256 (asymmetric) where only the auth service holds the private key

### Token Claims
Each token contains:
- `user_id` — User identifier
- `token_type` — "access" or "refresh" (prevents token confusion attacks)
- `iat` — Issued at timestamp
- `exp` — Expiration timestamp

### Token Type Validation
We validate `token_type` on decode to prevent:
- Using refresh tokens as access tokens
- Using access tokens to refresh (they should fail fast, not after DB lookup)

### Configuration
Environment variables:
- `JWT_ACCESS_TOKEN_LIFETIME` — Access token lifetime in seconds (default: 600 = 10 min)
- `JWT_REFRESH_TOKEN_LIFETIME` — Refresh token lifetime in seconds (default: 604800 = 7 days)

---

## Security – Step 4.2: Refresh Token Storage & Rotation

### Why Refresh Tokens Are Stored Hashed
We store a SHA-256 hash of refresh tokens, not the raw value:
- If the database is compromised, attackers can't use the hashes directly
- SHA-256 is sufficient because refresh tokens are already high-entropy (cryptographically random JWTs)
- Unlike passwords, we don't need bcrypt/argon2 since there's no brute-force risk on random tokens

### Why Token Rotation Exists
Each time a refresh token is used, we:
1. Invalidate the old token
2. Issue a new token pair
3. Link old → new via `replaced_by` for audit trail

Benefits:
- Limits token lifetime even if stolen
- Detects token theft (see below)
- Provides clear audit trail of token usage

### What Token Reuse Detection Means
If an already-rotated (revoked) refresh token is used:
1. This indicates the token was stolen and used by both attacker and legitimate user
2. We **revoke ALL refresh tokens** for that user as a security measure
3. We log a `TOKEN_REUSE_DETECTED` event for incident response
4. User must re-authenticate

This is a critical security feature: it turns token theft into a detectable event.

### API Endpoints
- `POST /api/auth/login/` — Authenticate, return token pair
- `POST /api/auth/refresh/` — Exchange refresh token for new pair
- `POST /api/auth/logout/` — Revoke refresh token

### Token Model
The `RefreshToken` model tracks:
- `token_hash` — SHA-256 of raw token (never store raw!)
- `jti` — Unique token identifier (JWT ID claim)
- `revoked_at` — When token was invalidated
- `replaced_by` — Points to token that replaced this one (rotation chain)

---

## Security – Step 4.3: Cookie-Based Refresh Tokens

### Why Refresh Tokens Should Not Be Accessible to JavaScript
Storing refresh tokens in localStorage or sessionStorage exposes them to XSS attacks. If an attacker injects malicious JavaScript, they can:
1. Read the token from storage
2. Send it to their server
3. Use it to generate access tokens indefinitely

**HttpOnly cookies cannot be read by JavaScript**, making them immune to XSS token theft.

### XSS vs CSRF Trade-off
Moving tokens to cookies introduces CSRF risk but eliminates XSS risk:

| Storage Method | XSS Risk | CSRF Risk |
|----------------|----------|-----------|
| localStorage   | HIGH     | None      |
| HttpOnly Cookie| None     | Requires protection |

We mitigate CSRF by:
- Requiring CSRF token header on refresh/logout
- Using SameSite=Lax cookies

### Why SameSite=Lax?
- **Strict**: Cookie never sent cross-site (breaks OAuth redirects, external links)
- **Lax**: Cookie sent on top-level navigation GET requests (good balance)
- **None**: Cookie always sent (requires Secure, enables cross-site tracking)

Lax provides CSRF protection for POST requests while allowing normal navigation.

### Why Access Token Is Still in Header
- Access tokens are short-lived (10 min), limiting exposure window
- APIs typically expect Bearer token in Authorization header
- Keeps API stateless and compatible with mobile/third-party clients
- Frontend stores access token in memory only (not localStorage)

### Updated API Flow
1. `GET /api/auth/csrf/` — Get CSRF token (sets cookie)
2. `POST /api/auth/login/` — Returns access token JSON, sets refresh cookie
3. `POST /api/auth/refresh/` — Requires CSRF header, reads cookie, returns new access token
4. `POST /api/auth/logout/` — Requires CSRF header, clears cookie

### Frontend Integration
```javascript
// Get CSRF token first
const csrfResponse = await fetch('/api/auth/csrf/', { credentials: 'include' });
const { csrfToken } = await csrfResponse.json();

// Refresh token (cookie sent automatically)
const refreshResponse = await fetch('/api/auth/refresh/', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRFToken': csrfToken,
  },
});
```

### Cookie Settings
- `REFRESH_TOKEN_COOKIE_HTTPONLY = True` — No JS access
- `REFRESH_TOKEN_COOKIE_SECURE = True` — HTTPS only (in production)
- `REFRESH_TOKEN_COOKIE_SAMESITE = 'Lax'` — CSRF protection
- `REFRESH_TOKEN_COOKIE_PATH = '/api/auth/'` — Minimize exposure