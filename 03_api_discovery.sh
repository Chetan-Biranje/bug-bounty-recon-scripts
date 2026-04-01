#!/bin/bash
# ============================================================
# 03_api_discovery.sh
# API endpoint discovery via ffuf, waybackurls, gau, and JS
# Usage: ./03_api_discovery.sh <domain> [wordlist]
# Example: ./03_api_discovery.sh target.com
# ============================================================

set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "[ERROR] No domain provided."
    echo "Usage: $0 <domain> [optional_wordlist]"
    exit 1
fi

DOMAIN="$1"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="output/${DOMAIN}_api_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

# Default wordlist — override with second argument
WORDLIST="${2:-/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt}"
if [[ ! -f "$WORDLIST" ]]; then
    # Fallback — create a minimal built-in wordlist
    WORDLIST="$OUTPUT_DIR/api_wordlist.txt"
    cat > "$WORDLIST" <<'EOF'
api
api/v1
api/v2
api/v3
api/v1/users
api/v1/user
api/v1/admin
api/v1/login
api/v1/logout
api/v1/register
api/v1/profile
api/v1/account
api/v1/accounts
api/v1/orders
api/v1/order
api/v1/products
api/v1/product
api/v1/search
api/v1/upload
api/v1/download
api/v1/export
api/v1/import
api/v1/config
api/v1/settings
api/v1/health
api/v1/status
api/v1/docs
api/v1/swagger
api/v1/graphql
api/v2/users
api/v2/login
api/v2/admin
graphql
swagger
swagger.json
swagger-ui.html
swagger/index.html
openapi.json
openapi.yaml
api-docs
api-docs/swagger.json
docs/api
v1
v2
v3
admin
admin/api
internal
internal/api
backend
backend/api
EOF
    echo "[WARN] SecLists not found — using built-in wordlist (install SecLists for better results)"
fi

# Base URL — try HTTPS first
BASE_URL="https://${DOMAIN}"

echo "============================================"
echo " API Discovery — $DOMAIN"
echo " Output: $OUTPUT_DIR"
echo "============================================"

# ── Step 1: Passive — Wayback Machine ────────────────────────
echo ""
echo "[*] Step 1/5 — Passive API recon (Wayback Machine)"
if command -v waybackurls &>/dev/null; then
    waybackurls "$DOMAIN" 2>/dev/null \
        | grep -iE "(api|/v[0-9]+/|graphql|swagger|openapi)" \
        | sort -u \
        > "$OUTPUT_DIR/wayback_api.txt"
    echo "[+] Wayback API URLs: $(wc -l < "$OUTPUT_DIR/wayback_api.txt")"
else
    echo "[SKIP] waybackurls not installed"
    touch "$OUTPUT_DIR/wayback_api.txt"
fi

# ── Step 2: Passive — GAU ────────────────────────────────────
echo ""
echo "[*] Step 2/5 — Passive API recon (gau)"
if command -v gau &>/dev/null; then
    gau "$DOMAIN" 2>/dev/null \
        | grep -iE "(api|/v[0-9]+/|graphql|swagger|openapi)" \
        | sort -u \
        > "$OUTPUT_DIR/gau_api.txt"
    echo "[+] GAU API URLs: $(wc -l < "$OUTPUT_DIR/gau_api.txt")"
else
    echo "[SKIP] gau not installed"
    touch "$OUTPUT_DIR/gau_api.txt"
fi

# ── Step 3: Active — ffuf directory brute ────────────────────
echo ""
echo "[*] Step 3/5 — Active API endpoint fuzzing (ffuf)"
if command -v ffuf &>/dev/null; then
    ffuf -u "${BASE_URL}/FUZZ" \
         -w "$WORDLIST" \
         -mc 200,201,204,301,302,307,400,401,403,405 \
         -fc 404 \
         -t 40 \
         -timeout 10 \
         -o "$OUTPUT_DIR/ffuf_api.json" \
         -of json \
         -s 2>/dev/null || true

    # Parse ffuf JSON output
    if [[ -f "$OUTPUT_DIR/ffuf_api.json" ]]; then
        jq -r '.results[]? | "\(.status) \(.url)"' \
            "$OUTPUT_DIR/ffuf_api.json" \
            > "$OUTPUT_DIR/ffuf_api.txt" 2>/dev/null || true
        echo "[+] ffuf found: $(wc -l < "$OUTPUT_DIR/ffuf_api.txt") endpoints"
    fi
else
    echo "[SKIP] ffuf not installed"
    touch "$OUTPUT_DIR/ffuf_api.txt"
fi

# ── Step 4: Check for API documentation exposure ─────────────
echo ""
echo "[*] Step 4/5 — Checking for exposed API documentation"
DOC_PATHS=(
    "swagger.json"
    "swagger-ui.html"
    "swagger/index.html"
    "api-docs"
    "api-docs/swagger.json"
    "v1/swagger.json"
    "v2/swagger.json"
    "openapi.json"
    "openapi.yaml"
    "api/swagger.json"
    "docs"
    "graphql"
    "graphiql"
    ".well-known/openapi.json"
)

touch "$OUTPUT_DIR/exposed_docs.txt"
for path in "${DOC_PATHS[@]}"; do
    url="${BASE_URL}/${path}"
    status=$(curl -s -o /dev/null -w "%{http_code}" \
                  --connect-timeout 5 \
                  --max-time 8 \
                  -L "$url" 2>/dev/null || echo "000")
    if [[ "$status" =~ ^(200|201|301|302)$ ]]; then
        echo "[FOUND] [$status] $url" | tee -a "$OUTPUT_DIR/exposed_docs.txt"
    fi
done

COUNT=$(wc -l < "$OUTPUT_DIR/exposed_docs.txt")
echo "[+] Exposed docs/specs found: $COUNT"

# ── Step 5: Merge all findings ───────────────────────────────
echo ""
echo "[*] Step 5/5 — Merging all findings"
cat "$OUTPUT_DIR/wayback_api.txt" \
    "$OUTPUT_DIR/gau_api.txt" \
    "$OUTPUT_DIR/ffuf_api.txt" \
    "$OUTPUT_DIR/exposed_docs.txt" \
    2>/dev/null \
    | sort -u \
    > "$OUTPUT_DIR/all_api_endpoints.txt"

echo ""
echo "============================================"
echo " DONE — $DOMAIN"
echo "============================================"
echo " Wayback URLs   : $OUTPUT_DIR/wayback_api.txt"
echo " GAU URLs       : $OUTPUT_DIR/gau_api.txt"
echo " ffuf results   : $OUTPUT_DIR/ffuf_api.txt"
echo " Exposed docs   : $OUTPUT_DIR/exposed_docs.txt"
echo " ALL endpoints  : $OUTPUT_DIR/all_api_endpoints.txt"
echo " Total unique   : $(wc -l < "$OUTPUT_DIR/all_api_endpoints.txt")"
echo "============================================"
