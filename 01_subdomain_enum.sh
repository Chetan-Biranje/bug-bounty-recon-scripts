#!/bin/bash
# ============================================================
# 01_subdomain_enum.sh
# Subdomain enumeration + alive check + port scan
# Usage: ./01_subdomain_enum.sh <domain>
# Example: ./01_subdomain_enum.sh target.com
# ============================================================

set -euo pipefail

# ── Input validation ─────────────────────────────────────────
if [[ $# -eq 0 ]]; then
    echo "[ERROR] No domain provided."
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN="$1"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="output/${DOMAIN}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

echo "============================================"
echo " Subdomain Enumeration — $DOMAIN"
echo " Output: $OUTPUT_DIR"
echo "============================================"

# ── Tool check ───────────────────────────────────────────────
for tool in subfinder httpx nmap; do
    if ! command -v "$tool" &>/dev/null; then
        echo "[WARN] $tool not found — skipping steps that need it"
    fi
done

# ── Step 1: Passive subdomain enumeration with subfinder ─────
echo ""
echo "[*] Step 1/5 — Passive subdomain enumeration (subfinder)"
if command -v subfinder &>/dev/null; then
    subfinder -d "$DOMAIN" \
              -silent \
              -o "$OUTPUT_DIR/subs_subfinder.txt" 2>/dev/null
    echo "[+] subfinder found $(wc -l < "$OUTPUT_DIR/subs_subfinder.txt") subdomains"
else
    echo "[SKIP] subfinder not installed"
    touch "$OUTPUT_DIR/subs_subfinder.txt"
fi

# ── Step 2: Certificate transparency (crt.sh) ────────────────
echo ""
echo "[*] Step 2/5 — Certificate transparency logs (crt.sh)"
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null \
    | jq -r '.[].name_value' 2>/dev/null \
    | sed 's/\*\.//g' \
    | sort -u \
    > "$OUTPUT_DIR/subs_crtsh.txt" || touch "$OUTPUT_DIR/subs_crtsh.txt"
echo "[+] crt.sh found $(wc -l < "$OUTPUT_DIR/subs_crtsh.txt") entries"

# ── Step 3: Merge and deduplicate ────────────────────────────
echo ""
echo "[*] Step 3/5 — Merging and deduplicating"
cat "$OUTPUT_DIR"/subs_*.txt \
    | sort -u \
    | grep -v "^\*" \
    | grep "\." \
    > "$OUTPUT_DIR/all_subdomains.txt"
TOTAL=$(wc -l < "$OUTPUT_DIR/all_subdomains.txt")
echo "[+] Total unique subdomains: $TOTAL"

# ── Step 4: Alive check with httpx ───────────────────────────
echo ""
echo "[*] Step 4/5 — Probing alive subdomains (httpx)"
if command -v httpx &>/dev/null; then
    httpx -l "$OUTPUT_DIR/all_subdomains.txt" \
          -status-code \
          -title \
          -tech-detect \
          -follow-redirects \
          -threads 50 \
          -silent \
          -o "$OUTPUT_DIR/alive_subs.txt" 2>/dev/null
    ALIVE=$(wc -l < "$OUTPUT_DIR/alive_subs.txt")
    echo "[+] Alive subdomains: $ALIVE"
else
    echo "[SKIP] httpx not installed — using curl fallback"
    while IFS= read -r sub; do
        if curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" \
                "https://$sub" 2>/dev/null | grep -qE "^[23]"; then
            echo "$sub" >> "$OUTPUT_DIR/alive_subs.txt"
        fi
    done < "$OUTPUT_DIR/all_subdomains.txt"
fi

# ── Step 5: Quick port scan on alive hosts ───────────────────
echo ""
echo "[*] Step 5/5 — Port scan on alive hosts (nmap)"
if command -v nmap &>/dev/null && [[ -s "$OUTPUT_DIR/alive_subs.txt" ]]; then
    # Extract just hostnames from httpx output
    awk '{print $1}' "$OUTPUT_DIR/alive_subs.txt" \
        | sed 's|https\?://||' \
        | cut -d/ -f1 \
        | sort -u \
        > "$OUTPUT_DIR/hosts_clean.txt"

    nmap -iL "$OUTPUT_DIR/hosts_clean.txt" \
         -p 80,443,8080,8443,8000,8888,3000,9000,9090 \
         --open \
         -T4 \
         -oN "$OUTPUT_DIR/portscan.txt" 2>/dev/null
    echo "[+] Port scan complete — see portscan.txt"
else
    echo "[SKIP] nmap not installed or no alive hosts"
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo "============================================"
echo " DONE — $DOMAIN"
echo "============================================"
echo " All subdomains : $OUTPUT_DIR/all_subdomains.txt"
echo " Alive hosts    : $OUTPUT_DIR/alive_subs.txt"
echo " Port scan      : $OUTPUT_DIR/portscan.txt"
echo "============================================"
