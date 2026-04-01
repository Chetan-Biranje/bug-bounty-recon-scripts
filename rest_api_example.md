# Example — REST API Threat Model

> Worked example: E-commerce order API.
> Endpoints: GET/POST/DELETE on `/api/v1/orders`

---

## 1. System

**API:** Order Management API
**Endpoints:**
```
GET    /api/v1/orders          → list current user's orders
GET    /api/v1/orders/{id}     → get one order
POST   /api/v1/orders          → create order
DELETE /api/v1/orders/{id}     → cancel order (owner only)
GET    /api/v1/admin/orders    → list ALL orders (admin only)
```
**Auth:** JWT Bearer token (HS256, 15-min expiry)

---

## 2. Data Flow

```
[Mobile App / Browser]
     │
     │  Authorization: Bearer eyJ...
     ▼
[API Gateway — rate limiting, auth check]
     │
     ▼
[Order Service — Node.js Express]
     │
     │  SELECT / INSERT / DELETE
     ▼
[PostgreSQL — orders table]

Trust boundary: Internet ↔ API Gateway
Trust boundary: API Gateway ↔ Order Service
Trust boundary: Order Service ↔ Database
```

---

## 3. Full STRIDE Analysis

### GET /api/v1/orders/{id} — Highest IDOR risk

| Threat | Attack Scenario | Risk | Control | Status |
|---|---|---|---|---|
| **S** | Attacker sends expired JWT | HIGH | Verify `exp` claim on every request | ✅ |
| **S** | Attacker uses another user's JWT | HIGH | Signature verification — any modification = invalid | ✅ |
| **T — IDOR** | User A requests `/orders/9988` (belongs to User B) — gets User B's order data | CRITICAL | After auth: `if (order.user_id !== req.user.id) return 403` | ❌ **MISSING** |
| **T** | Mass assignment — PATCH body includes `"status":"shipped"` | HIGH | Allowlist accepted fields: only `{ notes, delivery_instructions }` | ✅ |
| **R** | Order access not logged | MEDIUM | Log every order fetch: `{ user_id, order_id, ip, timestamp }` | 🔄 |
| **I** | Response includes full user PII of order owner | MEDIUM | Return only fields caller needs — exclude `user.phone`, `user.address_full` | ❌ **MISSING** |
| **D** | No pagination — `GET /orders` returns 50,000 records | HIGH | Mandatory pagination: default 20, max 100 | ✅ |
| **E** | Regular user hits `GET /admin/orders` | CRITICAL | Admin middleware: `if (req.user.role !== 'admin') return 403` | ✅ |

---

### POST /api/v1/orders — Business logic risks

| Threat | Attack Scenario | Risk | Control | Status |
|---|---|---|---|---|
| **T** | Attacker sends `"price": 0.01` in request body | CRITICAL | Price NEVER accepted from client — always calculated server-side from product catalog | ✅ |
| **T** | Attacker sends `"user_id": 999` to create order as another user | HIGH | `user_id` always taken from JWT, never from request body | ✅ |
| **T** | Attacker sends `"status": "delivered"` at order creation | HIGH | `status` field set server-side to `"pending"` always, not accepted from client | ✅ |
| **D** | Attacker creates 10,000 orders in 1 minute | HIGH | Rate limit: 10 order creations per user per hour | ❌ **MISSING** |
| **S** | JWT missing — unauthenticated order creation | CRITICAL | Auth middleware rejects if no valid JWT | ✅ |

---

### DELETE /api/v1/orders/{id} — Privilege issues

| Threat | Attack Scenario | Risk | Control | Status |
|---|---|---|---|---|
| **E** | User A deletes User B's order | CRITICAL | Check `order.user_id === req.user.id` before delete | ❌ **MISSING** |
| **E** | Regular user deletes any order | CRITICAL | Same ownership check | ❌ **MISSING** |
| **R** | Deletion not logged | HIGH | Immutable audit log: `{ event: "order_deleted", user_id, order_id, timestamp }` | 🔄 |
| **T** | Order already shipped — deletion should be blocked | MEDIUM | Business logic: only `pending` orders can be cancelled | ✅ |

---

## 4. Critical Findings

| # | Finding | Endpoint | Risk |
|---|---|---|---|
| 1 | **IDOR** — no ownership check on GET order | `GET /orders/{id}` | CRITICAL |
| 2 | **IDOR** — no ownership check on DELETE | `DELETE /orders/{id}` | CRITICAL |
| 3 | **Excessive data exposure** — PII in response | `GET /orders/{id}` | HIGH |
| 4 | **No rate limit** on order creation | `POST /orders` | HIGH |
| 5 | **Audit logging incomplete** | Multiple | MEDIUM |

---

## 5. Fix for IDOR (Code Example)

**Before (vulnerable):**
```javascript
app.get('/api/v1/orders/:id', authenticate, async (req, res) => {
  const order = await Order.findById(req.params.id);
  // ❌ No ownership check — any authenticated user gets this order
  res.json(order);
});
```

**After (fixed):**
```javascript
app.get('/api/v1/orders/:id', authenticate, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });

  // ✅ Object-level authorization
  if (order.user_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  // ✅ Return only needed fields
  res.json({
    id:         order.id,
    status:     order.status,
    created_at: order.created_at,
    items:      order.items,
    total:      order.total
    // Never return: user.phone, user.full_address, payment_method_details
  });
});
```
