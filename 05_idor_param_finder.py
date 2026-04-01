#!/usr/bin/env python3
"""
05_idor_param_finder.py
Find IDOR-prone parameters from a list of URLs.
Identifies numeric IDs, GUIDs, hashed values in URLs and query params.

Usage:
    python3 05_idor_param_finder.py -f urls.txt
    python3 05_idor_param_finder.py -d target.com
    cat urls.txt | python3 05_idor_param_finder.py --stdin
"""

import argparse
import re
import sys
import json
import subprocess
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from datetime import datetime
import os

# ── IDOR detection patterns ───────────────────────────────────────────────────

# Parameters in URL path or query string that are IDOR-prone
IDOR_PARAM_NAMES = {
    # High confidence
    "id", "user_id", "userId", "account_id", "accountId",
    "order_id", "orderId", "invoice_id", "invoiceId",
    "profile_id", "profileId", "customer_id", "customerId",
    "document_id", "documentId", "file_id", "fileId",
    "message_id", "messageId", "ticket_id", "ticketId",
    "report_id", "reportId", "record_id", "recordId",
    "member_id", "memberId", "employee_id", "employeeId",
    # Medium confidence
    "uid", "pid", "cid", "oid", "rid", "mid",
    "ref", "token", "key", "hash", "uuid", "guid",
    "object_id", "objectId", "resource_id", "resourceId",
    "project_id", "projectId", "org_id", "orgId",
    "team_id", "teamId", "group_id", "groupId",
}

# Value patterns that indicate IDOR candidates
VALUE_PATTERNS = {
    "numeric_id":     r'^\d{1,15}$',
    "uuid_v4":        r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
    "uuid_any":       r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    "short_hash":     r'^[0-9a-f]{8,16}$',
    "long_hash":      r'^[0-9a-f]{32,64}$',
    "base64_id":      r'^[A-Za-z0-9+/]{8,}={0,2}$',
    "numeric_path":   r'/\d{1,15}(?:/|$)',
}

# Path segments that suggest object IDs
IDOR_PATH_PATTERNS = [
    r'/users?/(\d+)',
    r'/accounts?/(\d+)',
    r'/orders?/(\d+)',
    r'/invoices?/(\d+)',
    r'/profiles?/(\d+)',
    r'/documents?/(\d+)',
    r'/files?/(\d+)',
    r'/messages?/(\d+)',
    r'/reports?/(\d+)',
    r'/tickets?/(\d+)',
    r'/[a-z_-]+/(\d{1,15})(?:/|$)',           # generic numeric path segment
    r'/[a-z_-]+/([0-9a-f]{8}-[0-9a-f-]{27})', # generic UUID path segment
]


def classify_value(value: str) -> str | None:
    """Return pattern type if value looks like an IDOR candidate, else None."""
    for name, pattern in VALUE_PATTERNS.items():
        if re.match(pattern, value, re.IGNORECASE):
            return name
    return None


def analyze_url(url: str) -> list[dict]:
    """Return list of IDOR candidates found in this URL."""
    findings = []
    try:
        parsed = urlparse(url)
    except Exception:
        return findings

    # ── Check query parameters ────────────────────────────────
    try:
        params = parse_qs(parsed.query, keep_blank_values=False)
    except Exception:
        params = {}

    for param_name, values in params.items():
        for value in values:
            value = value.strip()
            # High confidence: param name is IDOR-prone
            if param_name.lower() in IDOR_PARAM_NAMES:
                vtype = classify_value(value) or "named_param"
                findings.append({
                    "url":        url,
                    "type":       "query_param",
                    "param":      param_name,
                    "value":      value,
                    "value_type": vtype,
                    "confidence": "HIGH" if vtype in ("numeric_id", "uuid_v4", "uuid_any") else "MEDIUM",
                })
            # Medium confidence: value looks like an ID
            elif value:
                vtype = classify_value(value)
                if vtype in ("numeric_id", "uuid_v4", "uuid_any"):
                    findings.append({
                        "url":        url,
                        "type":       "query_param",
                        "param":      param_name,
                        "value":      value,
                        "value_type": vtype,
                        "confidence": "MEDIUM",
                    })

    # ── Check URL path ────────────────────────────────────────
    path = parsed.path
    for pattern in IDOR_PATH_PATTERNS:
        matches = re.findall(pattern, path, re.IGNORECASE)
        for match in matches:
            vtype = classify_value(match) or "path_segment"
            findings.append({
                "url":        url,
                "type":       "path_segment",
                "param":      "path",
                "value":      match,
                "value_type": vtype,
                "confidence": "HIGH" if vtype in ("numeric_id", "uuid_v4", "uuid_any") else "MEDIUM",
            })

    return findings


def load_urls_from_domain(domain: str) -> list[str]:
    """Use waybackurls / gau to get URLs from domain."""
    urls = set()
    for tool in ["waybackurls", "gau"]:
        try:
            result = subprocess.run(
                [tool, domain],
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("http"):
                    urls.add(line)
            print(f"[+] {tool}: {len(urls)} URLs collected")
        except FileNotFoundError:
            print(f"[SKIP] {tool} not installed")
        except subprocess.TimeoutExpired:
            print(f"[WARN] {tool} timed out")

    return list(urls)


def print_finding(f: dict):
    color = "\033[31m" if f["confidence"] == "HIGH" else "\033[33m"
    reset = "\033[0m"
    print(f"  {color}[{f['confidence']}]{reset} "
          f"[{f['type']}] "
          f"param={f['param']} "
          f"value={f['value']} "
          f"({f['value_type']})")
    print(f"           {f['url']}")


def main():
    parser = argparse.ArgumentParser(description="IDOR-prone parameter finder")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file",   help="File with URLs (one per line)")
    group.add_argument("-d", "--domain", help="Domain to pull URLs from (uses waybackurls/gau)")
    group.add_argument("--stdin",        action="store_true", help="Read URLs from stdin")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    parser.add_argument("--high-only",   action="store_true", help="Show HIGH confidence only")
    args = parser.parse_args()

    # Load URLs
    urls = []
    if args.file:
        with open(args.file) as f:
            urls = [line.strip() for line in f if line.strip().startswith("http")]
        print(f"[*] Loaded {len(urls)} URLs from {args.file}")
    elif args.domain:
        print(f"[*] Fetching URLs for {args.domain}...")
        urls = load_urls_from_domain(args.domain)
    elif args.stdin:
        urls = [line.strip() for line in sys.stdin if line.strip().startswith("http")]
        print(f"[*] Read {len(urls)} URLs from stdin")

    if not urls:
        print("[!] No URLs to analyze. Exiting.")
        sys.exit(1)

    # Analyze
    print(f"[*] Analyzing {len(urls)} URLs for IDOR candidates...")
    all_findings = []
    high_count = 0
    medium_count = 0
    seen_urls = defaultdict(list)

    for url in urls:
        findings = analyze_url(url)
        for f in findings:
            if args.high_only and f["confidence"] != "HIGH":
                continue
            all_findings.append(f)
            seen_urls[url].append(f)
            if f["confidence"] == "HIGH":
                high_count += 1
            else:
                medium_count += 1

    # Print results
    print(f"\n{'='*60}")
    print(f"  IDOR CANDIDATES FOUND")
    print(f"{'='*60}")

    for url, findings in seen_urls.items():
        if findings:
            for f in findings:
                print_finding(f)

    # Write output
    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = args.domain or "manual"

    txt_file  = f"{args.output}/idor_candidates_{slug}_{ts}.txt"
    json_file = f"{args.output}/idor_candidates_{slug}_{ts}.json"

    with open(txt_file, "w") as f:
        for finding in all_findings:
            f.write(
                f"[{finding['confidence']}] [{finding['type']}] "
                f"param={finding['param']} value={finding['value']} "
                f"({finding['value_type']})\n"
                f"  URL: {finding['url']}\n\n"
            )

    with open(json_file, "w") as f:
        json.dump(all_findings, f, indent=2)

    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"  URLs analyzed        : {len(urls)}")
    print(f"  HIGH confidence IDOR : {high_count}")
    print(f"  MEDIUM confidence    : {medium_count}")
    print(f"\n  Results (txt)  → {txt_file}")
    print(f"  Results (json) → {json_file}")
    print()

    if high_count > 0:
        print(f"  ⚠️  {high_count} HIGH confidence IDOR candidates found!")
        print(f"     Test manually — create 2 accounts, swap the IDs, see what leaks.")


if __name__ == "__main__":
    main()
