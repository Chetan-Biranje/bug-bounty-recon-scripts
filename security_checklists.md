# Security Checklists

---

## Web Application Security Checklist

### Authentication
- [ ] Passwords hashed with bcrypt / Argon2 (cost factor ≥ 12)
- [ ] No MD5 / SHA1 / plain text password storage
- [ ] Brute force protection: rate limiting + account lockout
- [ ] MFA available (TOTP preferred)
- [ ] No username enumeration (identical error for wrong user / wrong pass)
- [ ] Secure password reset (random token, tied to user, TTL ≤ 15 min, one-time use)
- [ ] Session regenerated after login

### Session Management
- [ ] Session tokens are cryptographically random (min 128 bits)
- [ ] `HttpOnly` flag on session cookies
- [ ] `Secure` flag on session cookies (HTTPS only)
- [ ] `SameSite=Strict` or `SameSite=Lax`
- [ ] Session timeout: idle (30 min) and absolute (24 hr)
- [ ] Session invalidated on logout (server-side)

### Authorization
- [ ] Every route has authorization check
- [ ] Deny by default — explicit allowlist per role
- [ ] Object-level authorization: verify caller owns the resource
- [ ] No authorization based on client-supplied data (role in request body)
- [ ] Admin routes separated and protected

### Input Validation
- [ ] All inputs validated server-side (never client-side only)
- [ ] Allowlist validation (define what's valid, reject everything else)
- [ ] Input length limits on all fields
- [ ] File uploads: MIME type check from magic bytes, size limit, UUID filename

### Output Encoding
- [ ] HTML output encoded to prevent XSS
- [ ] JSON responses have correct `Content-Type: application/json`
- [ ] No user input reflected in response without encoding

### Error Handling
- [ ] Generic error messages to users
- [ ] Detailed errors only in server logs
- [ ] No stack traces, file paths, DB errors in responses
- [ ] 404 and 403 don't reveal whether resource exists (for sensitive objects)

### Security Headers
- [ ] `Content-Security-Policy`
- [ ] `X-Frame-Options: DENY`
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- [ ] `Referrer-Policy: strict-origin-when-cross-origin`
- [ ] `Permissions-Policy`
- [ ] Remove: `X-Powered-By`, `Server`

### Transport Security
- [ ] HTTPS enforced everywhere
- [ ] HTTP redirects to HTTPS (301)
- [ ] HSTS header present
- [ ] TLS 1.2+ only (TLS 1.0 and 1.1 disabled)
- [ ] No mixed content (HTTP assets on HTTPS page)

### Third-Party / Dependencies
- [ ] Dependencies audited (`npm audit`, `pip-audit`)
- [ ] No dependencies with known critical CVEs
- [ ] Dependency versions pinned
- [ ] CSP restricts third-party script sources

---

## API Security Checklist (OWASP API Top 10)

### Authentication and Authorization
- [ ] Every endpoint requires authentication (no accidental public endpoints)
- [ ] JWT: algorithm explicitly validated (reject `alg:none`, only accept HS256/RS256)
- [ ] JWT: short access token TTL (≤ 15 min)
- [ ] JWT: signature verified on every request
- [ ] Object-level auth (BOLA): `resource.owner === caller` check on every object access
- [ ] Function-level auth: roles explicitly checked per endpoint

### Input and Output
- [ ] Mass assignment prevented: allowlist accepted fields per endpoint
- [ ] Response filtered: return only fields caller needs (no excessive data exposure)
- [ ] Request body size limited
- [ ] All inputs validated and sanitized

### Rate Limiting and DoS
- [ ] Rate limiting on all public endpoints
- [ ] Rate limiting on authentication endpoints (strict)
- [ ] Pagination mandatory on all list endpoints (max page size enforced)
- [ ] File upload: size limit enforced

### Configuration
- [ ] Swagger / API docs NOT accessible in production (or behind auth)
- [ ] Debug endpoints disabled in production
- [ ] CORS: explicit allowlist (never `Access-Control-Allow-Origin: *` on authenticated endpoints)
- [ ] Old API versions decommissioned (v1 if v3 is current)
- [ ] No secrets, credentials, tokens in API responses

---

## Authentication Security Checklist

### Password Policy
- [ ] Minimum 8 characters (12+ recommended)
- [ ] No maximum length restriction (or max ≥ 64)
- [ ] Check against breached password list (HaveIBeenPwned API)
- [ ] No complexity requirements that encourage weak patterns (Password1!)
- [ ] Allow paste in password fields

### Password Storage
- [ ] bcrypt with cost factor ≥ 12, OR Argon2id
- [ ] Unique salt per password (handled by bcrypt/Argon2 automatically)
- [ ] No reversible encryption of passwords

### Brute Force Protection
- [ ] Rate limit: max 5 attempts per IP per minute on login
- [ ] Account lockout after N failures (or progressive delay)
- [ ] Lockout alert sent to user (not just silent lock)
- [ ] Lockout bypass not possible by rotating IPs (consider user-level lockout)

### MFA
- [ ] TOTP (Google Authenticator, Authy) preferred over SMS
- [ ] SMS OTP: short TTL (5 min), one-time use, rate limited
- [ ] Backup codes: provided at enrollment, hashed in DB, one-time use
- [ ] MFA cannot be bypassed by skipping the step in the auth flow
- [ ] MFA re-enrollment requires current authentication

### JWT Specific
- [ ] Secret: cryptographically random, min 256 bits, stored in env var
- [ ] `alg` header validated server-side — `none` rejected
- [ ] `exp` claim present and checked
- [ ] `iss` claim validated if multi-tenant
- [ ] Token not stored in localStorage (XSS accessible) — use HttpOnly cookie
- [ ] Refresh token rotation: old refresh token invalidated on use
- [ ] Refresh tokens revocable (stored in DB, checked on use)
