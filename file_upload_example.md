# Example — File Upload Threat Model

> Worked example: Profile photo upload feature.
> Endpoint: POST /api/v1/users/avatar

---

## 1. System

**Feature:** User uploads a profile photo.
**Flow:**
1. User selects image in browser
2. Browser POSTs multipart form to `/api/v1/users/avatar`
3. Server validates file
4. Server stores file in S3 bucket
5. Server saves S3 URL to database
6. Server returns public URL to user

---

## 2. Data Flow

```
[Browser — file selected]
     │
     │  POST /api/v1/users/avatar
     │  Content-Type: multipart/form-data
     │  Authorization: Bearer JWT
     ▼
[API Server — Node.js]
     │  Validate: size, MIME type, filename
     │  Rename: UUID-based filename
     ▼
[AWS S3 — private bucket]
     │  Signed URL issued on read
     ▼
[Database — stores S3 key]

Trust boundary: Internet ↔ API Server
Trust boundary: API Server ↔ S3
```

---

## 3. STRIDE Analysis

| Threat | Attack Scenario | Risk | Control | Status |
|---|---|---|---|---|
| **S** | Unauthenticated user uploads file | HIGH | JWT auth required before processing | ✅ |
| **T — Web Shell** | Attacker uploads `shell.php` — gains code execution | CRITICAL | Allowlist MIME types: `image/jpeg`, `image/png`, `image/webp` only. Verify with `file-type` lib, not just extension | ✅ |
| **T — Path Traversal** | Filename: `../../etc/passwd` — stored outside intended directory | HIGH | Generate UUID filename server-side, discard original filename entirely | ✅ |
| **T — Zip Bomb** | Upload `bomb.zip` disguised as image — CPU/memory exhaustion on extraction | MEDIUM | Never extract archives. Process only accepted image types. | N/A |
| **T — ImageTragick** | Malformed image exploits ImageMagick CVE | HIGH | Use safe image processing lib (Sharp.js), keep deps updated | ✅ |
| **T — SVG XSS** | Upload SVG containing `<script>alert(1)</script>` | HIGH | SVG explicitly excluded from allowed types | ✅ |
| **T — Polyglot** | File is valid JPEG and valid PHP simultaneously | HIGH | MIME type verified from file magic bytes (not extension), re-encode image with Sharp before storage | ✅ |
| **I — Direct S3 Access** | S3 bucket is public — anyone can access any file by URL | HIGH | Bucket is private. Generate presigned URL (15-min expiry) per request | ✅ |
| **I — Filename Leaks Username** | Stored as `john_doe_avatar.jpg` — enumerable | MEDIUM | Stored as `UUID.jpg` — e.g. `a3f9e2c1-...jpg` | ✅ |
| **D — Disk/Storage Exhaustion** | User uploads 10GB file | HIGH | Max file size: 5MB enforced at upload (before processing) | ✅ |
| **D — Upload Flood** | User uploads 1,000 files per minute | HIGH | Rate limit: 10 uploads per user per hour | ❌ **MISSING** |
| **E — Overwrite Another User's File** | Attacker guesses S3 key and overwrites | MEDIUM | S3 key includes `user_id` prefix: `avatars/{user_id}/{uuid}.jpg` — IAM policy restricts writes per prefix | ✅ |
| **E — SSRF via URL** | If server fetches file from URL instead of upload — attacker sends `http://169.254.169.254` | CRITICAL | No URL-fetch upload — only direct multipart upload accepted | N/A |

---

## 4. Critical Findings

| # | Finding | Risk | Fix |
|---|---|---|---|
| 1 | No rate limit on upload | HIGH | Add: 10 uploads/user/hour |

---

## 5. Secure Upload Implementation (Node.js)

```javascript
const multer = require('multer');
const sharp  = require('sharp');
const { v4: uuidv4 } = require('uuid');
const { fromBuffer } = require('file-type');

// ✅ Memory storage — process before writing anywhere
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }  // 5MB hard limit
});

app.post('/api/v1/users/avatar', authenticate, upload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file provided' });

  // ✅ Verify MIME from magic bytes — not extension, not Content-Type header
  const detected = await fromBuffer(req.file.buffer);
  const allowed  = ['image/jpeg', 'image/png', 'image/webp'];

  if (!detected || !allowed.includes(detected.mime)) {
    return res.status(400).json({ error: 'Only JPEG, PNG, WebP allowed' });
  }

  // ✅ Re-encode with Sharp — strips EXIF, kills polyglots, normalizes format
  let processed;
  try {
    processed = await sharp(req.file.buffer)
      .resize(400, 400, { fit: 'cover' })   // normalize size
      .jpeg({ quality: 85 })                // force JPEG output
      .toBuffer();
  } catch {
    return res.status(400).json({ error: 'Invalid image' });
  }

  // ✅ UUID filename — never use original filename
  const key = `avatars/${req.user.id}/${uuidv4()}.jpg`;

  await s3.putObject({
    Bucket: process.env.S3_BUCKET,
    Key:    key,
    Body:   processed,
    ContentType: 'image/jpeg',
    // ✅ No ACL: 'public-read' — bucket is private
  }).promise();

  await User.update({ avatar_key: key }, { where: { id: req.user.id } });

  res.json({ message: 'Avatar updated' });
  // Note: Never return the direct S3 URL — serve via presigned URL endpoint
});
```

---

## 6. Key Lessons

- **Never trust the file extension** — verify magic bytes with `file-type` or equivalent
- **Always re-encode images** — Sharp/Pillow re-encoding kills polyglots, strips EXIF GPS data, and neutralizes embedded payloads
- **UUID filenames always** — original filename is attacker-controlled data
- **Private S3 bucket + presigned URLs** — public buckets are a single misconfiguration away from data breach
- **SVG is not a safe image format** — it's XML and can contain scripts
