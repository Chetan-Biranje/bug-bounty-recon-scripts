# Threat Model Template — Web Application

> Copy this template for every new feature or system you threat model.
> Fill in each section. Leave nothing blank — if something doesn't apply, write "N/A — reason".

---

## 1. Scope

**Feature / System name:**
**Date:**
**Author:**
**Reviewers:**
**Version:**

**What does this system do?**
_(One paragraph. Plain English. No jargon.)_

---

## 2. Architecture Overview

**Tech stack:**
- Frontend:
- Backend:
- Database:
- Auth mechanism:
- External services:

**Deployment:**
- [ ] Cloud (AWS / GCP / Azure)
- [ ] On-premise
- [ ] Hybrid

---

## 3. Data Flow Diagram (DFD)

Paste your DFD here. Use [Threat Dragon](https://threatdragon.github.io/) or [draw.io](https://draw.io).

**Components to include:**
- External entities (users, third-party services, browsers)
- Processes (web server, API, background jobs)
- Data stores (databases, caches, file storage)
- Data flows (arrows between components)
- Trust boundaries (dashed lines — where privilege changes)

```
[User Browser] ──HTTP──► [Web Server] ──query──► [Database]
                              │
                              └──calls──► [External Payment API]

Trust boundary: Internet ↔ Internal network
Trust boundary: Web tier ↔ Database tier
```

---

## 4. Assets

_What are we protecting? What would hurt if compromised?_

| Asset | Sensitivity | Location |
|---|---|---|
| User PII (name, email, phone) | HIGH | Database |
| User passwords | CRITICAL | Database (hashed) |
| Session tokens | HIGH | Cookie / localStorage |
| API keys / secrets | CRITICAL | Environment variables |
| Payment data | CRITICAL | Payment processor (not stored locally) |
| Business logic data | MEDIUM | Database |

---

## 5. Trust Boundaries

_Where does trust level change?_

| Boundary | From | To | Risk |
|---|---|---|---|
| Internet → App | Untrusted user | Web server | HIGH |
| App → Database | Web server | DB | MEDIUM |
| App → External API | Web server | Third party | MEDIUM |

---

## 6. STRIDE Analysis

For each data flow and component, apply STRIDE.

---

### 6.1 User → Web Application

| Threat Type | Threat Description | Likelihood | Impact | Risk | Mitigation |
|---|---|---|---|---|---|
| **Spoofing** | Attacker steals session cookie and replays | MEDIUM | HIGH | HIGH | HttpOnly + Secure cookie flags, short session TTL |
| **Tampering** | Attacker modifies POST body to change price / role | HIGH | HIGH | CRITICAL | Server-side validation, allowlist accepted fields |
| **Repudiation** | User denies submitting malicious input | LOW | MEDIUM | LOW | Audit log all write actions with user_id + IP |
| **Info Disclosure** | Error page reveals stack trace | MEDIUM | MEDIUM | MEDIUM | Generic error messages, detailed logs server-side only |
| **DoS** | Attacker floods login endpoint | MEDIUM | HIGH | HIGH | Rate limiting per IP, CAPTCHA after N failures |
| **EoP** | Regular user accesses `/admin` route | MEDIUM | CRITICAL | CRITICAL | Role check middleware on every route |

---

### 6.2 Web Application → Database

| Threat Type | Threat Description | Likelihood | Impact | Risk | Mitigation |
|---|---|---|---|---|---|
| **Spoofing** | App connects with overprivileged DB user | LOW | HIGH | MEDIUM | Dedicated DB user with minimum required privileges |
| **Tampering** | SQL injection via user input | MEDIUM | CRITICAL | CRITICAL | Parameterized queries / ORM only, no raw string concat |
| **Repudiation** | DB changes not attributed to app action | LOW | MEDIUM | LOW | App-level audit log before DB write |
| **Info Disclosure** | DB error leaks schema / table names | MEDIUM | MEDIUM | MEDIUM | Catch DB errors, return generic message |
| **DoS** | Unbounded query returns millions of rows | LOW | HIGH | MEDIUM | Pagination, query timeouts, connection pool limits |
| **EoP** | App DB user can DROP TABLE | LOW | CRITICAL | HIGH | Read/write only — no DDL permissions for app user |

---

### 6.3 Web Application → External API

| Threat Type | Threat Description | Likelihood | Impact | Risk | Mitigation |
|---|---|---|---|---|---|
| **Spoofing** | Response from external API is forged / MITM | LOW | HIGH | MEDIUM | Verify TLS certificate, pin if critical |
| **Tampering** | External API response trusted blindly | MEDIUM | HIGH | HIGH | Validate and sanitize all external API responses |
| **Repudiation** | External API call not logged | LOW | MEDIUM | LOW | Log all outgoing API calls with request/response |
| **Info Disclosure** | API key sent in URL | LOW | CRITICAL | HIGH | API keys in Authorization header, never in URL |
| **DoS** | External API goes down, cascading failure | MEDIUM | HIGH | HIGH | Timeout + circuit breaker pattern |
| **EoP** | N/A for this flow | — | — | — | — |

---

## 7. Risk Summary

| Risk | Count |
|---|---|
| CRITICAL | _fill in_ |
| HIGH | _fill in_ |
| MEDIUM | _fill in_ |
| LOW | _fill in_ |

---

## 8. Mitigations Tracking

| # | Threat | Mitigation | Owner | Status | Ticket |
|---|---|---|---|---|---|
| 1 | SQLi on login | Parameterized queries | Dev team | ✅ Done | — |
| 2 | No rate limit on login | Add rate limiter middleware | Dev team | 🔄 In progress | #123 |
| 3 | Stack trace in errors | Generic error handler | Dev team | ❌ Not started | #124 |

---

## 9. Out of Scope

_What are you explicitly NOT covering in this threat model and why?_

- Infrastructure security (handled by DevOps team separately)
- DDoS at network layer (handled by CDN/WAF)

---

## 10. Review Sign-off

| Reviewer | Role | Date | Sign-off |
|---|---|---|---|
| | AppSec Engineer | | |
| | Lead Developer | | |
| | Product Owner | | |
