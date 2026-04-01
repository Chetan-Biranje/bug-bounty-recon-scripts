# Example — Login System Threat Model

> Worked example using the login_flow_template. This is how you fill it in for a real feature.
> System: Simple username + password login for a web app.

---

## 1. Scope

**Feature:** User login — username + password
**Date:** 2026-03-01
**Author:** Chetan Biranje
**System:** E-commerce web app — `/login` endpoint

**What does it do?**
Accepts username and password via POST request. Verifies credentials against the database. Issues a JWT (15-minute access token + 7-day refresh token) stored in HttpOnly cookies.

---

## 2. Data Flow Diagram

```
[User Browser]
     │
     │  POST /login  { "username": "...", "password": "..." }
     ▼
[Web Server — Express.js]
     │
     │  SELECT * FROM users WHERE email = ? (parameterized)
     ▼
[PostgreSQL Database]
     │
     │  Returns { user_id, email, password_hash, role }
     ▼
[Web Server — bcrypt.compare(password, hash)]
     │
     │  If match → sign JWT → set cookie
     ▼
[User Browser — HttpOnly cookie set]

Trust boundary: Internet ↔ Web Server
Trust boundary: Web Server ↔ Database
```

---

## 3. STRIDE Analysis

### User → Web Server (POST /login)

| Threat | Scenario | Risk | Control | Status |
|---|---|---|---|---|
| **S — Spoofing** | Attacker uses credential stuffing — 10,000 known username/password pairs from a breach | HIGH | Rate limit: 5 req/min per IP. Block after 10 failures for 15 min. | ✅ Implemented |
| **T — Tampering** | Attacker sends `' OR 1=1 --` in username field | CRITICAL | Parameterized query: `WHERE email = $1` | ✅ Implemented |
| **I — Info Disclosure** | Username enumeration: "Wrong password" vs "User not found" gives different messages | HIGH | Return identical: `"Invalid credentials"` for both cases | ✅ Fixed |
| **I — Info Disclosure** | Timing attack: `bcrypt.compare` takes longer for valid users (hash lookup done before compare) | MEDIUM | Compare always runs even for unknown users (dummy hash) | ✅ Implemented |
| **D — DoS** | Attacker sends 10,000 req/sec to `/login` | HIGH | Rate limit + CAPTCHA after 3 failures | 🔄 Partial — rate limit done, CAPTCHA pending |
| **R — Repudiation** | Failed login not logged — can't detect brute force attack in progress | MEDIUM | Log: `{ event: "login_failure", email_hash: sha256(email), ip, timestamp }` | ✅ Implemented |

---

### Web Server → Database

| Threat | Scenario | Risk | Control | Status |
|---|---|---|---|---|
| **T — Tampering** | SQL injection in query | CRITICAL | Parameterized query — no raw string concat | ✅ |
| **S — Spoofing** | App DB user has admin privileges | MEDIUM | App uses read-only DB user for login check | ✅ |
| **I — Info Disclosure** | DB error leaks schema — `PG::UndefinedTable` in response | HIGH | Global error handler catches DB errors, returns `500 Internal Server Error` | ✅ |
| **D — DoS** | Unbounded queries — no connection pool timeout | MEDIUM | Connection pool: max 20 connections, 5s timeout | ✅ |

---

### JWT Issuance

| Threat | Scenario | Risk | Control | Status |
|---|---|---|---|---|
| **T — Tampering** | Attacker sends JWT with `"alg": "none"` | CRITICAL | Server rejects any token where alg ≠ `HS256` | ✅ |
| **T — Tampering** | Attacker modifies `"role": "user"` to `"role": "admin"` in payload | CRITICAL | Server verifies signature on every request — modified payload = invalid sig | ✅ |
| **S — Spoofing** | JWT secret is `"secret"` — brute forced in seconds | CRITICAL | Secret: 256-bit random from `crypto.randomBytes(32)` stored in env var | ✅ |
| **I — Info Disclosure** | JWT payload contains PII (email, phone) | MEDIUM | Payload contains only: `{ user_id, role, iat, exp }` | ✅ |
| **T — Tampering** | Access token never expires | HIGH | Access token TTL: 15 min. Refresh token TTL: 7 days. | ✅ |

---

### Cookie Security

| Threat | Scenario | Risk | Control | Status |
|---|---|---|---|---|
| **S — Spoofing** | XSS payload reads `document.cookie` and steals session | HIGH | `HttpOnly: true` on access + refresh token cookies | ✅ |
| **T — Tampering** | Cookie sent over HTTP — intercepted by MITM | CRITICAL | `Secure: true` — cookie only sent over HTTPS | ✅ |
| **S — Spoofing** | CSRF — attacker tricks user's browser into sending authenticated request | HIGH | `SameSite: Strict` on session cookie | ✅ |
| **S — Spoofing** | Session fixation — attacker sets their session ID before login | MEDIUM | New session/token issued on every successful login | ✅ |

---

## 4. Findings Summary

| # | Threat | Risk | Status |
|---|---|---|---|
| 1 | Credential stuffing — no rate limit | CRITICAL | ✅ Fixed |
| 2 | SQL injection in username | CRITICAL | ✅ Fixed |
| 3 | JWT alg:none accepted | CRITICAL | ✅ Fixed |
| 4 | JWT secret too weak | CRITICAL | ✅ Fixed |
| 5 | Username enumeration via error message | HIGH | ✅ Fixed |
| 6 | Cookie missing HttpOnly | HIGH | ✅ Fixed |
| 7 | DB error message leaked | HIGH | ✅ Fixed |
| 8 | CAPTCHA missing on login | MEDIUM | 🔄 Pending — ticket #234 |
| 9 | PII in JWT payload | MEDIUM | ✅ Fixed |

---

## 5. Lessons Learned

- **Rate limiting** is the single highest-ROI control on a login endpoint. Implement it first.
- **Identical error messages** are easy to overlook — developers naturally write helpful errors. Must be explicitly reviewed.
- **JWT secrets** in `.env.example` files are often copied verbatim to production. Always generate fresh secrets, never hardcode defaults.
- **CAPTCHA** is always "pending" — prioritize it or it never ships.
