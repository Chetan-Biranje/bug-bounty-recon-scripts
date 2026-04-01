#!/usr/bin/env python3
"""
02_js_analysis.py
Extract API endpoints and potential secrets from JavaScript files.

Usage:
    python3 02_js_analysis.py -d target.com
    python3 02_js_analysis.py -f urls.txt
    python3 02_js_analysis.py -u https://target.com/static/app.js
"""

import argparse
import re
import sys
import os
import json
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── Regex patterns ───────────────────────────────────────────────────────────

# API endpoint patterns
ENDPOINT_PATTERNS = [
    r'["\'`](/api/[^\s"\'`<>]{3,100})',
    r'["\'`](/v[0-9]+/[^\s"\'`<>]{3,100})',
    r'["\'`](https?://[^\s"\'`<>]{5,200})',
    r'fetch\(["\']([^"\']{5,200})["\']',
    r'axios\.[a-z]+\(["\']([^"\']{5,200})["\']',
    r'url:\s*["\']([^"\']{5,200})["\']',
    r'endpoint:\s*["\']([^"\']{5,200})["\']',
    r'baseURL:\s*["\']([^"\']{5,200})["\']',
    r'path:\s*["\']([/][^\s"\'`<>]{2,100})["\']',
]

# Secret / credential patterns — sorted by severity
SECRET_PATTERNS = {
    "AWS Access Key":       r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":       r'(?i)aws.{0,20}["\'][0-9a-zA-Z/+]{40}["\']',
    "Google API Key":       r'AIza[0-9A-Za-z\-_]{35}',
    "Slack Token":          r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    "GitHub Token":         r'gh[pousr]_[A-Za-z0-9_]{36,255}',
    "JWT Token":            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    "Bearer Token":         r'[Bb]earer\s+[A-Za-z0-9\-_\.=]{20,}',
    "Private Key":          r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
    "Generic API Key":      r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\'][A-Za-z0-9\-_]{16,}["\']',
    "Generic Secret":       r'(?i)(secret|passwd|password|token)\s*[=:]\s*["\'][^\s"\']{8,}["\']',
    "Firebase URL":         r'https://[a-z0-9-]+\.firebaseio\.com',
    "Hardcoded IP":         r'\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b',
}

# ── Helpers ──────────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
}

def fetch_url(url: str, timeout: int = 10) -> str | None:
    """Fetch URL content, return text or None on failure."""
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
        r.raise_for_status()
        return r.text
    except Exception:
        return None


def find_js_urls(domain: str) -> list[str]:
    """Find JS file URLs from a domain using waybackurls and gau if available."""
    js_urls = set()

    # Try fetching the page and extracting script tags
    for scheme in ["https", "http"]:
        content = fetch_url(f"{scheme}://{domain}")
        if content:
            found = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', content)
            for url in found:
                if url.startswith("http"):
                    js_urls.add(url)
                else:
                    js_urls.add(urljoin(f"{scheme}://{domain}", url))
            break

    # Try waybackurls if available
    try:
        import subprocess
        result = subprocess.run(
            ["waybackurls", domain],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines():
            if line.endswith(".js") or ".js?" in line:
                js_urls.add(line.strip())
    except Exception:
        pass

    return list(js_urls)


def analyze_js(url: str) -> dict:
    """Analyze a single JS file for endpoints and secrets."""
    result = {
        "url": url,
        "endpoints": [],
        "secrets": [],
        "error": None
    }

    content = fetch_url(url)
    if not content:
        result["error"] = "Failed to fetch"
        return result

    # Find endpoints
    endpoints = set()
    for pattern in ENDPOINT_PATTERNS:
        matches = re.findall(pattern, content)
        for m in matches:
            # Filter noise
            if len(m) > 5 and not m.endswith(('.png', '.jpg', '.css', '.ico')):
                endpoints.add(m)
    result["endpoints"] = sorted(endpoints)

    # Find secrets
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, content)
        for m in matches:
            result["secrets"].append({
                "type": secret_type,
                "value": m[:80] + "..." if len(m) > 80 else m
            })

    return result


def print_result(r: dict):
    """Pretty print analysis result."""
    print(f"\n{'='*60}")
    print(f"  JS FILE: {r['url']}")
    print(f"{'='*60}")

    if r.get("error"):
        print(f"  [ERROR] {r['error']}")
        return

    if r["secrets"]:
        print(f"\n  🚨 SECRETS FOUND ({len(r['secrets'])})")
        for s in r["secrets"]:
            print(f"     [{s['type']}] {s['value']}")

    if r["endpoints"]:
        print(f"\n  📡 ENDPOINTS ({len(r['endpoints'])})")
        for ep in r["endpoints"][:50]:  # cap display at 50
            print(f"     {ep}")
        if len(r["endpoints"]) > 50:
            print(f"     ... and {len(r['endpoints']) - 50} more (see JSON output)")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="JS file analyzer for bug bounty recon")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Target domain (auto-discovers JS files)")
    group.add_argument("-f", "--file",   help="File containing JS URLs (one per line)")
    group.add_argument("-u", "--url",    help="Single JS file URL")
    parser.add_argument("-o", "--output", help="Output directory (default: output/)", default="output")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads (default: 10)")
    args = parser.parse_args()

    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings()

    # Build JS URL list
    js_urls = []
    if args.domain:
        print(f"[*] Discovering JS files on {args.domain}...")
        js_urls = find_js_urls(args.domain)
        print(f"[+] Found {len(js_urls)} JS files")
    elif args.file:
        with open(args.file) as f:
            js_urls = [line.strip() for line in f if line.strip()]
    elif args.url:
        js_urls = [args.url]

    if not js_urls:
        print("[!] No JS URLs to analyze. Exiting.")
        sys.exit(1)

    # Analyze in parallel
    all_results = []
    all_endpoints = set()
    all_secrets = []

    print(f"[*] Analyzing {len(js_urls)} JS files with {args.threads} threads...")
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(analyze_js, url): url for url in js_urls}
        for future in as_completed(futures):
            r = future.result()
            all_results.append(r)
            print_result(r)
            all_endpoints.update(r["endpoints"])
            all_secrets.extend(r["secrets"])

    # Write output
    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain_slug = args.domain or "manual"

    endpoints_file = f"{args.output}/js_endpoints_{domain_slug}_{ts}.txt"
    secrets_file   = f"{args.output}/js_secrets_{domain_slug}_{ts}.txt"
    json_file      = f"{args.output}/js_full_{domain_slug}_{ts}.json"

    with open(endpoints_file, "w") as f:
        f.write("\n".join(sorted(all_endpoints)))

    with open(secrets_file, "w") as f:
        for s in all_secrets:
            f.write(f"[{s['type']}] {s['value']}\n")

    with open(json_file, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"  JS files analyzed : {len(js_urls)}")
    print(f"  Unique endpoints  : {len(all_endpoints)}")
    print(f"  Potential secrets : {len(all_secrets)}")
    print(f"\n  Endpoints → {endpoints_file}")
    print(f"  Secrets   → {secrets_file}")
    print(f"  Full JSON → {json_file}")

    if all_secrets:
        print(f"\n  ⚠️  {len(all_secrets)} potential secret(s) found — review manually!")


if __name__ == "__main__":
    main()
