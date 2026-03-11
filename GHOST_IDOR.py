#!/usr/bin/env python3
# ===============================================
# GHOST_IDOR.py — Identity Binding Analyzer
# Purpose: Detect unauthenticated account-context leaks
# Mode: Passive / GET-only / Hash-based comparison
# ===============================================

import requests
import hashlib
import json
import sys
import time

BANNER = """
=======================================================
  G H O S T _ I D O R  — Identity Binding Analyzer
  Mode: Passive | GET-only | Safe Recon
=======================================================
"""

ENDPOINTS = [
    "/api/account",
    "/api/profile",
    "/api/limits",
    "/api/wallets",
    "/api/balances"
]

HEADERS = {
    "User-Agent": "GhostIDOR/1.0 (Passive Research)",
    "Accept": "application/json",
}

def hash_body(body):
    return hashlib.sha256(body.encode("utf-8")).hexdigest()

def analyze_response(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        body = r.text.strip()
        body_hash = hash_body(body)

        try:
            parsed = json.loads(body)
            field_count = len(parsed.keys()) if isinstance(parsed, dict) else "N/A"
        except:
            field_count = "Non-JSON"

        return {
            "status": r.status_code,
            "length": len(body),
            "hash": body_hash,
            "fields": field_count,
            "preview": body[:120].replace("\n", "")
        }

    except Exception as e:
        return {"error": str(e)}

def main():
    if len(sys.argv) != 2:
        print("Usage: python GHOST_IDOR.py https://target-domain")
        sys.exit(1)

    base = sys.argv[1].rstrip("/")
    print(BANNER)
    print(f"[TARGET] {base}\n")

    results = {}

    for ep in ENDPOINTS:
        full = base + ep
        print(f"[CHECK] {ep}")
        data = analyze_response(full)
        results[ep] = data

        if "error" in data:
            print(f"  [ERROR] {data['error']}")
        else:
            print(f"  Status : {data['status']}")
            print(f"  Length : {data['length']}")
            print(f"  Hash   : {data['hash']}")
            print(f"  Fields : {data['fields']}")
            print(f"  Preview: {data['preview']}")
        print("-" * 55)
        time.sleep(0.8)

    print("\n[SUMMARY — HASH MAP]")
    for ep, data in results.items():
        if "hash" in data:
            print(f"{ep:<20} {data['hash']}")

    print("\n[INSTRUCTIONS]")
    print("• Run this tool from TWO clean sessions (browser / VM / OS)")
    print("• Compare hash outputs")
    print("• Identical hashes = identity NOT bound")
    print("• Divergent hashes = session or user bound")
    print("\n✔ Passive analysis complete")

if __name__ == "__main__":
    main()
