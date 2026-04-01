# Threat Model Template — Login / Authentication Flow

> Use this specifically for any login, registration, or password reset feature.

---

## 1. Flow Description

**What authentication mechanism is used?**
- [ ] Username + password
- [ ] SSO / OAuth (provider: ___)
- [ ] Magic link / passwordless
- [ ] MFA (type: ___)

**Draw the flow:**
```
User → [Enter credentials] → POST /login → [Verify password hash]
                                               │
                              ┌────────────────┴─────────────────┐
                           Success                              Failure
                              │                                   │
                    [Issue JWT / session]               [Return generic error]
                              │
                    [Set cookie / return token]
```

---

## 2. STRIDE on Login Flow — Step by Step

### Step 1: User submits credentials

| Threat | Description | Risk | Control |
|---|---|---|---|
| **S** | Credential stuffing with leaked credentials | HIGH | Rate limit + MFA |
| **T** | SQLi in username field | HIGH | Parameterized query |
| **T** | NoSQLi in JSON body | MEDIUM | Input validation |
| **I** | Username enumeration (timing attack) | MEDIUM | Constant-time comparison |
| **I** | Username enumeration (message difference) | HIGH | Same error for wrong user and wrong password |
| **D** | Brute force attack | CRITICAL | Rate limit: 5/min per IP, account lockout |

---

### Step 2: Server verifies credentials

| Threat | Description | Risk | Control |
|---|---|---|---|
| **T** | Password stored in plain text | CRITICAL | bcrypt / Argon2 with cost factor ≥ 12 |
| **T** | Password hashed with MD5 / SHA1 | CRITICAL | Migrate to bcrypt / Argon2 |
| **S** | Timing attack on password comparison | MEDIUM | Constant-time hash comparison |
| **R** | Failed login not logged | MEDIUM | Log: username attempt + IP + timestamp |

---

### Step 3: Session / token issued

| Threat | Description | Risk | Control |
|---|---|---|---|
| **S** | Predictable session token | CRITICAL | Cryptographically random token (min 128 bits) |
| **T** | JWT algorithm confusion (`alg:none`) | CRITICAL | Reject any alg except configured (HS256 or RS256) |
| **T** | JWT secret is weak | HIGH | Secret min 256 bits, stored in env var |
| **I** | Token contains sensitive data | MEDIUM | Only store user_id + role in JWT, not PII |
| **T** | Token doesn't expire | HIGH | Access token: 15 min; Refresh token: 7 days |
| **E** | JWT role claim can be modified by user | CRITICAL | Signature verification on every request |

---

### Step 4: Session cookie set

| Threat | Description | Risk | Control |
|---|---|---|---|
| **S** | Cookie theft via XSS | HIGH | `HttpOnly` flag on session cookie |
| **T** | Cookie sent over HTTP | CRITICAL | `Secure` flag, force HTTPS |
| **S** | CSRF using cookie | HIGH | `SameSite=Strict` or `SameSite=Lax` |
| **I** | Session fixation | MEDIUM | Regenerate session ID after successful login |

---

### Step 5: Password Reset Flow

| Threat | Description | Risk | Control |
|---|---|---|---|
| **S** | Attacker resets another user's password | CRITICAL | Token tied to specific user_id, one-time use |
| **I** | Reset token in URL (logged by browser, proxies) | HIGH | Token in request body, not URL |
| **T** | Predictable reset token | CRITICAL | Cryptographically random, min 128 bits |
| **D** | No expiry on reset token | HIGH | Token TTL: max 15 minutes |
| **E** | Reset flow allows setting blank password | MEDIUM | Enforce password policy on reset |
| **I** | Reset confirms if email exists | MEDIUM | Same response regardless of email existence |

---

### Step 6: MFA (if applicable)

| Threat | Description | Risk | Control |
|---|---|---|---|
| **S** | MFA bypass — skip MFA step directly | CRITICAL | Enforce MFA step before issuing full session |
| **T** | TOTP code brute force | HIGH | Rate limit TOTP attempts |
| **D** | No backup codes — user locked out | MEDIUM | Provide secure backup codes at enrollment |
| **E** | MFA enrollment without re-authentication | HIGH | Require password before changing MFA settings |

---

## 3. Security Headers Checklist

For the login page and auth API responses:

| Header | Required Value | Present? |
|---|---|---|
| `Content-Security-Policy` | Restrict script sources | ❌ / ✅ |
| `X-Frame-Options` | `DENY` | ❌ / ✅ |
| `Strict-Transport-Security` | `max-age=31536000` | ❌ / ✅ |
| `X-Content-Type-Options` | `nosniff` | ❌ / ✅ |
| `Cache-Control` | `no-store` on auth pages | ❌ / ✅ |

---

## 4. Risk Summary

| Threat | Risk | Owner | Status |
|---|---|---|---|
| No rate limit on login | CRITICAL | | |
| Password stored insecurely | CRITICAL | | |
| JWT alg:none accepted | CRITICAL | | |
| Username enumeration | HIGH | | |
| HttpOnly missing on cookie | HIGH | | |
