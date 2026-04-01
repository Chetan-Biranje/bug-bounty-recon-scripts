# Threat Model Template — REST API

---

## 1. Scope

**API name:**
**Base URL:**
**Date:**
**Author:**

**What does this API do?**

**Who calls this API?**
- [ ] Web frontend
- [ ] Mobile app
- [ ] Other internal services
- [ ] Third-party integrations

---

## 2. API Inventory

List every endpoint. This is your attack surface.

| Method | Endpoint | Auth Required | Roles Allowed | Sensitive Data |
|---|---|---|---|---|
| POST | /api/v1/login | No | — | Password |
| GET | /api/v1/users/{id} | Yes | Admin, Owner | PII |
| PUT | /api/v1/users/{id} | Yes | Owner only | PII |
| DELETE | /api/v1/users/{id} | Yes | Admin only | — |
| GET | /api/v1/orders | Yes | User (own only) | Order data |

---

## 3. Authentication Mechanism

- [ ] JWT (Bearer token)
- [ ] Session cookie
- [ ] API key
- [ ] OAuth 2.0
- [ ] mTLS

**Token details:**
- Algorithm:
- Expiry:
- Refresh mechanism:
- Storage location (client-side):

---

## 4. STRIDE Analysis — Per Endpoint Category

---

### Authentication Endpoints (`/login`, `/register`, `/reset-password`)

| Threat | Description | Risk | Control |
|---|---|---|---|
| **S** | Credential stuffing — attacker tries known username/password pairs | HIGH | Rate limiting, account lockout, MFA |
| **S** | Username enumeration via different error messages | MEDIUM | Return identical error for wrong user and wrong password |
| **T** | SQL injection in username field | HIGH | Parameterized queries |
| **T** | JWT algorithm confusion — send `alg:none` | HIGH | Explicitly validate algorithm, reject `none` |
| **R** | Failed login attempts not logged | MEDIUM | Log every failed attempt with IP + timestamp |
| **I** | Password reset token in URL (logged by proxies) | HIGH | Token in request body, not URL |
| **D** | No rate limiting — brute force possible | CRITICAL | Rate limit: 5 attempts per IP per minute |
| **E** | Attacker resets another user's password | CRITICAL | Tie reset token to specific user_id, short TTL |

---

### Resource Endpoints (`/users/{id}`, `/orders/{id}`, `/files/{id}`)

| Threat | Description | Risk | Control |
|---|---|---|---|
| **S** | Request with expired/forged JWT | HIGH | Verify signature and expiry on every request |
| **T** | Mass assignment — send `role:admin` in PUT body | HIGH | Allowlist accepted fields, never bind entire body to model |
| **T** | IDOR — user A accesses user B's resource by changing ID | CRITICAL | Check `resource.owner_id == request.user_id` on every access |
| **R** | Resource modification not attributed to user | MEDIUM | Log: user_id + action + resource_id + timestamp |
| **I** | Response returns more fields than needed | MEDIUM | Explicit response serialization — never return full DB object |
| **D** | List endpoint returns all records without pagination | HIGH | Mandatory pagination, max page size enforced |
| **E** | Regular user hits admin-only endpoint | CRITICAL | Role middleware on every route — deny by default |

---

### File Upload Endpoints (`/upload`, `/import`)

| Threat | Description | Risk | Control |
|---|---|---|---|
| **S** | Upload malicious file as legitimate user | MEDIUM | Authenticate + authorize before accepting file |
| **T** | Upload a web shell (.php, .jsp) | CRITICAL | Allowlist: only accept specific MIME types |
| **T** | Path traversal in filename (`../../etc/passwd`) | HIGH | Sanitize filename, generate UUID-based storage name |
| **I** | File stored at predictable public URL | MEDIUM | Signed URLs with expiry for private files |
| **D** | No file size limit — disk exhaustion | HIGH | Max file size enforced at upload |
| **D** | No limit on number of uploads per user | MEDIUM | Per-user upload quota |
| **E** | User downloads another user's private file | CRITICAL | Authorization check before serving any file |

---

### Admin Endpoints (`/admin/*`)

| Threat | Description | Risk | Control |
|---|---|---|---|
| **S** | Regular user accesses admin endpoint | CRITICAL | Admin role check on every admin route |
| **T** | Admin endpoint accepts mass assignment | HIGH | Strict input validation even for admin users |
| **R** | Admin actions not audited | HIGH | Immutable audit log for all admin actions |
| **I** | Admin endpoint exposed publicly | HIGH | Admin routes behind VPN or internal network only |
| **D** | Admin can trigger expensive operations without limit | MEDIUM | Rate limit admin bulk operations |
| **E** | Admin role assigned via API parameter | CRITICAL | Role assignment requires separate privileged flow |

---

## 5. OWASP API Security Top 10 Checklist

| # | Check | Status | Notes |
|---|---|---|---|
| API1 | Object-level authorization on every endpoint | ❌ / ✅ | |
| API2 | Authentication present and validated | ❌ / ✅ | |
| API3 | Object property-level authorization (no mass assignment) | ❌ / ✅ | |
| API4 | Rate limiting on all endpoints | ❌ / ✅ | |
| API5 | Function-level authorization (role checks) | ❌ / ✅ | |
| API6 | No unrestricted access to sensitive business flows | ❌ / ✅ | |
| API7 | SSRF prevention on server-side URL fetches | ❌ / ✅ | |
| API8 | No debug endpoints, no verbose errors in prod | ❌ / ✅ | |
| API9 | API versioning managed, old versions decommissioned | ❌ / ✅ | |
| API10 | Third-party API responses validated before use | ❌ / ✅ | |

---

## 6. Risk Summary and Mitigations

| Threat | Risk | Mitigation | Status |
|---|---|---|---|
| IDOR on `/users/{id}` | CRITICAL | Owner check middleware | 🔄 |
| No rate limit on `/login` | CRITICAL | Add rate limiter | ❌ |
| Mass assignment on PUT | HIGH | Allowlist fields | ✅ |
| JWT alg:none accepted | HIGH | Reject non-HS256/RS256 | ✅ |
