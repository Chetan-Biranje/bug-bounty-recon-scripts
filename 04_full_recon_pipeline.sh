#!/bin/bash
# ============================================================
# 04_full_recon_pipeline.sh
# Full automated recon pipeline — chains all scripts
# Usage: ./04_full_recon_pipeline.sh <domain>
# Example: ./04_full_recon_pipeline.sh target.com
# ============================================================

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Input ────────────────────────────────────────────────────
if [[ $# -eq 0 ]]; then
    echo -e "${RED}[ERROR]${NC} No domain provided."
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN="$1"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="output/${DOMAIN}_full_${TIMESTAMP}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$OUTPUT_DIR/pipeline.log"

mkdir -p "$OUTPUT_DIR"

# ── Logging ──────────────────────────────────────────────────
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

log_step() {
    log ""
    log "${CYAN}════════════════════════════════════════${NC}"
    log "${CYAN} $1${NC}"
    log "${CYAN}════════════════════════════════════════${NC}"
}

start_time=$(date +%s)

log ""
log "${BLUE}╔══════════════════════════════════════════╗${NC}"
log "${BLUE}║      Bug Bounty Recon Pipeline           ║${NC}"
log "${BLUE}║      Target: ${DOMAIN}${NC}"
log "${BLUE}║      Started: $(date)${NC}"
log "${BLUE}╚══════════════════════════════════════════╝${NC}"

# ── Step 1: Subdomain Enumeration ────────────────────────────
log_step "STEP 1/6 — Subdomain Enumeration"

SUB_DIR="$OUTPUT_DIR/1_subdomains"
mkdir -p "$SUB_DIR"

# crt.sh (no tool required)
log "[*] crt.sh passive enum..."
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null \
    | jq -r '.[].name_value' 2>/dev/null \
    | sed 's/\*\.//g' \
    | sort -u \
    > "$SUB_DIR/crtsh.txt" || touch "$SUB_DIR/crtsh.txt"
log "[+] crt.sh: $(wc -l < "$SUB_DIR/crtsh.txt") subdomains"

# subfinder
if command -v subfinder &>/dev/null; then
    log "[*] subfinder..."
    subfinder -d "$DOMAIN" -silent -o "$SUB_DIR/subfinder.txt" 2>/dev/null
    log "[+] subfinder: $(wc -l < "$SUB_DIR/subfinder.txt") subdomains"
else
    log "${YELLOW}[SKIP]${NC} subfinder not installed"
    touch "$SUB_DIR/subfinder.txt"
fi

# Merge
cat "$SUB_DIR"/*.txt | sort -u | grep "\." > "$SUB_DIR/all.txt"
log "[+] Total unique subdomains: $(wc -l < "$SUB_DIR/all.txt")"

# ── Step 2: Alive Check ───────────────────────────────────────
log_step "STEP 2/6 — Alive Check"

ALIVE_DIR="$OUTPUT_DIR/2_alive"
mkdir -p "$ALIVE_DIR"

if command -v httpx &>/dev/null; then
    log "[*] Probing with httpx..."
    httpx -l "$SUB_DIR/all.txt" \
          -status-code \
          -title \
          -tech-detect \
          -threads 50 \
          -silent \
          -o "$ALIVE_DIR/alive.txt" 2>/dev/null
else
    log "${YELLOW}[SKIP]${NC} httpx not installed — curl fallback"
    while IFS= read -r sub; do
        code=$(curl -s --connect-timeout 3 -o /dev/null \
                    -w "%{http_code}" "https://$sub" 2>/dev/null)
        [[ "$code" =~ ^[23] ]] && echo "https://$sub [$code]" \
            >> "$ALIVE_DIR/alive.txt"
    done < "$SUB_DIR/all.txt"
fi

ALIVE_COUNT=$(wc -l < "$ALIVE_DIR/alive.txt")
log "[+] Alive hosts: $ALIVE_COUNT"

# Extract clean hostnames
awk '{print $1}' "$ALIVE_DIR/alive.txt" \
    | sed 's|https\?://||' \
    | cut -d/ -f1 \
    | sort -u \
    > "$ALIVE_DIR/hosts.txt"

# ── Step 3: API Discovery ─────────────────────────────────────
log_step "STEP 3/6 — API Endpoint Discovery"

API_DIR="$OUTPUT_DIR/3_api"
mkdir -p "$API_DIR"

# Wayback + GAU
for tool in waybackurls gau; do
    if command -v "$tool" &>/dev/null; then
        log "[*] $tool..."
        "$tool" "$DOMAIN" 2>/dev/null \
            | grep -iE "(api|/v[0-9]+/|graphql|swagger|openapi)" \
            | sort -u \
            >> "$API_DIR/passive_api.txt" || true
    fi
done
touch "$API_DIR/passive_api.txt"
log "[+] Passive API URLs: $(sort -u "$API_DIR/passive_api.txt" | wc -l)"

# Exposed API docs check
DOC_PATHS=("swagger.json" "swagger-ui.html" "openapi.json" "openapi.yaml"
           "api-docs" "api/swagger.json" "v1/swagger.json" "graphql" "graphiql")

while IFS= read -r host; do
    for path in "${DOC_PATHS[@]}"; do
        url="https://${host}/${path}"
        status=$(curl -s -o /dev/null -w "%{http_code}" \
                      --connect-timeout 4 --max-time 6 "$url" 2>/dev/null || echo "000")
        if [[ "$status" =~ ^(200|201|301|302)$ ]]; then
            log "${GREEN}[FOUND]${NC} [$status] $url"
            echo "[$status] $url" >> "$API_DIR/exposed_docs.txt"
        fi
    done
done < "$ALIVE_DIR/hosts.txt"

touch "$API_DIR/exposed_docs.txt"
log "[+] Exposed API docs: $(wc -l < "$API_DIR/exposed_docs.txt")"

# ── Step 4: JS File Analysis ──────────────────────────────────
log_step "STEP 4/6 — JavaScript File Analysis"

JS_DIR="$OUTPUT_DIR/4_js"
mkdir -p "$JS_DIR"

if command -v python3 &>/dev/null && [[ -f "$SCRIPT_DIR/02_js_analysis.py" ]]; then
    log "[*] Running JS analysis..."
    python3 "$SCRIPT_DIR/02_js_analysis.py" \
            -d "$DOMAIN" \
            -o "$JS_DIR" 2>/dev/null || log "${YELLOW}[WARN]${NC} JS analysis had errors"
else
    log "${YELLOW}[SKIP]${NC} JS analysis script not found or python3 missing"
fi

# ── Step 5: Nuclei Scan ───────────────────────────────────────
log_step "STEP 5/6 — Nuclei Vulnerability Scan"

NUCLEI_DIR="$OUTPUT_DIR/5_nuclei"
mkdir -p "$NUCLEI_DIR"

if command -v nuclei &>/dev/null; then
    log "[*] Updating nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null || true

    log "[*] Running nuclei (high/critical only)..."
    nuclei -l "$ALIVE_DIR/alive.txt" \
           -t exposures/ \
           -t misconfiguration/ \
           -t cves/ \
           -severity high,critical \
           -o "$NUCLEI_DIR/findings.txt" \
           -silent 2>/dev/null || true

    NUCLEI_COUNT=$(wc -l < "$NUCLEI_DIR/findings.txt" 2>/dev/null || echo 0)
    if [[ "$NUCLEI_COUNT" -gt 0 ]]; then
        log "${RED}[!] Nuclei found $NUCLEI_COUNT issue(s) — review $NUCLEI_DIR/findings.txt${NC}"
    else
        log "[+] Nuclei: No high/critical issues found"
    fi
else
    log "${YELLOW}[SKIP]${NC} nuclei not installed"
fi

# ── Step 6: Final Report ──────────────────────────────────────
log_step "STEP 6/6 — Generating Report"

REPORT="$OUTPUT_DIR/REPORT.md"
end_time=$(date +%s)
duration=$((end_time - start_time))

cat > "$REPORT" <<EOF
# Recon Report — $DOMAIN
**Date:** $(date)
**Duration:** ${duration}s

---

## Summary

| Item | Count |
|---|---|
| Total subdomains found | $(wc -l < "$SUB_DIR/all.txt") |
| Alive hosts | $ALIVE_COUNT |
| Passive API URLs | $(sort -u "$API_DIR/passive_api.txt" | wc -l) |
| Exposed API docs | $(wc -l < "$API_DIR/exposed_docs.txt") |

---

## Alive Hosts

\`\`\`
$(cat "$ALIVE_DIR/alive.txt")
\`\`\`

---

## Exposed API Documentation

\`\`\`
$(cat "$API_DIR/exposed_docs.txt")
\`\`\`

---

## Passive API Endpoints (sample — top 50)

\`\`\`
$(sort -u "$API_DIR/passive_api.txt" | head -50)
\`\`\`

---

## Nuclei Findings

\`\`\`
$(cat "$NUCLEI_DIR/findings.txt" 2>/dev/null || echo "No findings or nuclei not installed")
\`\`\`

---

## Next Manual Steps

- [ ] Review all alive hosts — map functionality
- [ ] Test every exposed API doc endpoint for BOLA/IDOR
- [ ] Check JS findings for leaked secrets
- [ ] Test authentication on all login endpoints
- [ ] Look for parameter tampering on numeric IDs
- [ ] Check for rate limiting on sensitive endpoints
EOF

log ""
log "${GREEN}════════════════════════════════════════${NC}"
log "${GREEN} PIPELINE COMPLETE — ${DOMAIN}${NC}"
log "${GREEN} Duration: ${duration}s${NC}"
log "${GREEN}════════════════════════════════════════${NC}"
log ""
log " 📁 Output folder  : $OUTPUT_DIR"
log " 📄 Report         : $REPORT"
log " 🌐 Subdomains     : $SUB_DIR/all.txt"
log " ✅ Alive hosts    : $ALIVE_DIR/alive.txt"
log " 🔌 API endpoints  : $API_DIR/"
log " 📜 JS analysis    : $JS_DIR/"
log " 🔴 Nuclei         : $NUCLEI_DIR/"
