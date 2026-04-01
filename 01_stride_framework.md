# 01 — STRIDE Framework

> STRIDE is a threat classification model developed by Microsoft. It gives you a systematic way to think about every possible threat to a system before writing a line of code.

---

## Why Threat Modeling Exists

Fixing a security issue in production costs ~30x more than fixing it at design time.
Threat modeling forces you to think like an attacker **before** the attacker gets there.

**Four questions every threat model answers:**
1. What are we building?
2. What can go wrong?
3. What are we doing about it?
4. Did we do a good job?

---

## STRIDE — Full Reference

---

### S — Spoofing Identity

**Definition:** Attacker pretends to be a legitimate user, system, or component.

**What to look for:**
- Can you log in as another user?
- Can you forge a request that looks like it came from a trusted service?
- Is authentication missing on any endpoint?
- Can tokens/cookies be stolen and reused?

**Common vulnerabilities:**
- No authentication on sensitive endpoints
- Predictable session tokens
- JWT with `alg:none` accepted
- Broken password reset (attacker resets another user's password)
- OAuth state parameter missing (CSRF on login)

**Controls:**
- Strong authentication (MFA where possible)
- Cryptographically random session tokens
- JWT signature verification (reject `alg:none`)
- Secure password reset flow (token tied to user + short expiry)

**CVSS base metric:** Scope — usually Unchanged unless service-to-service

---

### T — Tampering with Data

**Definition:** Attacker modifies data — in transit, at rest, or in processing.

**What to look for:**
- Can a user modify their request to change another user's data?
- Can parameters be tampered to change prices, quantities, roles?
- Is data integrity verified at the server?
- Is any security decision made based on client-supplied data?

**Common vulnerabilities:**
- Mass assignment (extra fields in POST/PUT accepted by server)
- Price tampering in e-commerce (send `price=0.01` in checkout)
- HTTP parameter pollution
- SQL injection (tampers with database queries)
- File path traversal (tampers with file read location)
- Client-side validation only (server trusts client input)

**Controls:**
- Server-side validation on all inputs
- Allowlist what fields are accepted (never blindly bind request body to model)
- Parameterized queries
- HTTPS for all data in transit
- Database integrity constraints

---

### R — Repudiation

**Definition:** Attacker performs an action and then denies doing it. Or system has no way to prove who did what.

**What to look for:**
- Are sensitive actions (login, data change, delete, payment) logged?
- Do logs include enough context (user ID, IP, timestamp, action)?
- Can logs be tampered by an attacker who gains access?
- Is there a way to attribute every action to an authenticated identity?

**Common vulnerabilities:**
- No audit logging on sensitive actions
- Logs stored in the same place an attacker could access
- Logs without user ID — can't attribute actions
- Admin actions not logged

**Controls:**
- Immutable audit log for sensitive actions
- Log: who + what + when + from where
- Store logs in separate, write-only storage
- Include: `user_id`, `action`, `resource_id`, `timestamp`, `ip_address`

**Log entry example:**
```json
{
  "timestamp": "2026-04-01T12:34:56Z",
  "user_id": "usr_12345",
  "action": "DELETE",
  "resource": "orders/9988",
  "ip": "203.0.113.42",
  "user_agent": "Mozilla/5.0..."
}
```

---

### I — Information Disclosure

**Definition:** Sensitive data is exposed to unauthorized parties.

**What to look for:**
- Do error messages reveal stack traces, file paths, DB queries?
- Are internal IPs, server versions, or framework names in headers?
- Is sensitive data returned in API responses that isn't needed?
- Are debug endpoints left enabled in production?
- Is PII included in URLs (logs capture URLs)?

**Common vulnerabilities:**
- Verbose error messages (`PG::UndefinedTable: ERROR: relation "users" does not exist`)
- Swagger/API docs exposed in production
- `X-Powered-By: Express 4.18.2` header (reveals stack)
- Excessive data exposure in API response (returns full user object when only name needed)
- Sensitive data in URL query params (`?token=abc&password=xyz`)
- `.git` folder accessible on web root
- Backup files accessible (`backup.zip`, `db.sql`)

**Controls:**
- Generic error messages to users, detailed logs server-side only
- Remove `X-Powered-By`, `Server` headers
- Return only fields the caller needs (principle of minimum disclosure)
- Never put secrets in URLs
- Disable directory listing
- Remove debug/dev endpoints before production

---

### D — Denial of Service

**Definition:** Attacker disrupts availability of the service for legitimate users.

**What to look for:**
- Is there rate limiting on any user-facing endpoint?
- Can a single user exhaust a resource (CPU, memory, DB connections, storage)?
- Are there expensive operations (file processing, search, report generation) without limits?
- Can an unauthenticated user trigger heavy work?

**Common vulnerabilities:**
- No rate limiting on login endpoint (password spray without lockout)
- No rate limiting on registration (spam account creation)
- File upload without size limit (disk exhaustion)
- Regular expression with catastrophic backtracking (ReDoS)
- XML bomb / deeply nested JSON (parser exhaustion)
- No pagination on list endpoints (return all 1M records)
- Sending large payload to crash parser

**Controls:**
- Rate limiting per IP and per user on all public endpoints
- Request body size limits
- Pagination on all list endpoints
- Async processing for heavy operations (don't process inline)
- Input length limits on all fields
- ReDoS-safe regex patterns

---

### E — Elevation of Privilege

**Definition:** Attacker gains permissions they were not granted.

**What to look for:**
- Can a regular user access admin-only endpoints?
- Can a user act on behalf of another user (IDOR)?
- Can a user change their own role?
- Is authorization checked on every request, or only at login?

**Common vulnerabilities:**
- IDOR (accessing `/api/orders/1234` when logged in as different user)
- Broken function-level authorization (`/admin/deleteUser` accessible by regular users)
- JWT role claim tampering (modify `"role":"user"` to `"role":"admin"`)
- Mass assignment of `role` field (`{"name":"test","role":"admin"}` accepted in registration)
- Privilege escalation via password reset (reset admin's password)
- Horizontal privilege escalation (user A accesses user B's data)
- Vertical privilege escalation (user accesses admin functionality)

**Controls:**
- Server-side authorization check on every request (never trust client role claims)
- RBAC with allowlist (explicitly define what each role can do)
- Object-level authorization (verify caller owns the resource)
- Never derive permissions from user-supplied data
- Principle of least privilege for all roles

---

## STRIDE Applied to Components

When you look at a system, apply STRIDE to **every component and data flow:**

| Component | Apply STRIDE |
|---|---|
| User → Web App | Can user spoof identity? Tamper requests? |
| Web App → Database | Can queries be injected? Connection credentials safe? |
| Web App → External API | Is the external API authenticated? Is response trusted blindly? |
| Browser → API | Is transport encrypted? Are responses filtered? |
| Admin → System | Are admin actions logged? Is admin access audited? |

---

## STRIDE Quick Cheatsheet

```
Feature: User login
─────────────────────────────────────────────────────
S  Can attacker log in as someone else?
   → Test: brute force, credential stuffing, password reset flaw

T  Can attacker modify the login request to bypass checks?
   → Test: parameter tampering, JWT alg:none, SQL injection in username

R  Is the login action logged with enough context?
   → Test: check logs after login — is user_id + IP + timestamp present?

I  Does a failed login reveal whether username exists?
   → Test: try valid username + wrong pass vs invalid username + wrong pass

D  Can attacker lock out a user or overwhelm the login endpoint?
   → Test: rapid-fire requests — is there rate limiting? Account lockout?

E  Can attacker escalate to admin after login?
   → Test: inspect JWT claims, try modifying role, access /admin endpoints
```

---

## Process for Running a Threat Model Session

1. **Define scope** — what system/feature are you modeling?
2. **Draw Data Flow Diagram (DFD)** — users, processes, data stores, external entities, data flows, trust boundaries
3. **Apply STRIDE** to every component and data flow in the DFD
4. **Rate each threat** — likelihood × impact → risk score
5. **Define mitigations** for each accepted risk
6. **Track as tickets** — every unmitigated threat becomes a backlog item

---

*Next: [Templates →](./02_templates/)*
