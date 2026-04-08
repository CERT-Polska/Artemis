#!/usr/bin/env python3
"""
PoC verification script — demonstrates the CORS misconfiguration detection logic
works correctly against a local test server.

Usage:
    1. Start the test server:   python test/data/cors_test_app/app.py &
    2. Run this script:         python poc_cors_verify.py

No Artemis infrastructure (Redis, Karton, Postgres) needed — this exercises the
core detection functions directly.
"""

import sys
import threading
import time

import requests


# ---------- Core detection logic (extracted from artemis/modules/cors_scanner.py) ----------


def test_origin(url: str, origin: str) -> dict:
    """Send a request with a given Origin header and check the CORS response."""
    response = requests.get(url, headers={"Origin": origin}, timeout=5)
    return {
        "acao": response.headers.get("access-control-allow-origin", ""),
        "acac": response.headers.get("access-control-allow-credentials", ""),
    }


def is_misconfigured(acao: str, acac: str, test_origin: str) -> bool:
    """
    A CORS policy is exploitable when the server reflects an attacker-controlled
    origin AND allows credentials.  Without credentials the browser blocks
    cookie-authenticated reads even if ACAO matches.
    """
    if acac.lower() != "true":
        return False
    return acao == test_origin or acao == "*"


def scan_cors(url: str) -> list:
    """Run the full CORS probe battery against a URL.  Returns list of findings."""
    origins_to_test = [
        "https://evil.com",
        "null",
    ]
    findings = []

    for origin in origins_to_test:
        cors = test_origin(url, origin)
        if is_misconfigured(cors["acao"], cors["acac"], origin):
            findings.append(
                {
                    "origin": origin,
                    "acao": cors["acao"],
                    "acac": cors["acac"],
                }
            )

    return findings


# ---------- Inline test server (same logic as test/data/cors_test_app/app.py) ----------


def _start_test_server() -> None:
    """Start a minimal Flask server with intentional CORS misconfigurations."""
    try:
        from flask import Flask, Response, request as flask_request
    except ImportError:
        print("ERROR: flask not installed.  pip install flask", file=sys.stderr)
        sys.exit(1)

    app = Flask(__name__)

    @app.route("/vulnerable")
    def vulnerable() -> Response:
        origin = flask_request.headers.get("Origin", "")
        resp = Response("sensitive data", status=200)
        if origin:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    @app.route("/safe")
    def safe() -> Response:
        resp = Response("public data", status=200)
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp

    @app.route("/")
    def index() -> Response:
        return Response("hello", status=200)

    import logging

    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)
    app.run(host="127.0.0.1", port=18088, use_reloader=False)


# ---------- Main ----------


def main() -> None:
    print("=" * 60)
    print("  Artemis CORS Scanner — PoC Verification")
    print("=" * 60)
    print()

    # Start the embedded test server in a background thread
    server_thread = threading.Thread(target=_start_test_server, daemon=True)
    server_thread.start()
    time.sleep(1)  # wait for the server to bind

    base = "http://127.0.0.1:18088"
    passed = 0
    failed = 0

    # --- Test 1: vulnerable endpoint (reflected origin + credentials) ---
    print("[TEST 1] Vulnerable endpoint — reflected Origin + ACAC:true")
    findings = scan_cors(f"{base}/vulnerable")
    if findings and findings[0]["origin"] == "https://evil.com":
        print(f"  PASS  found {len(findings)} finding(s): {findings[0]}")
        passed += 1
    else:
        print(f"  FAIL  expected findings, got: {findings}")
        failed += 1

    # --- Test 2: safe endpoint (wildcard without credentials) ---
    print("[TEST 2] Safe endpoint — ACAO:* without credentials")
    findings = scan_cors(f"{base}/safe")
    if not findings:
        print("  PASS  no findings (correct)")
        passed += 1
    else:
        print(f"  FAIL  unexpected findings: {findings}")
        failed += 1

    # --- Test 3: no CORS headers at all ---
    print("[TEST 3] No CORS headers — default deny")
    findings = scan_cors(f"{base}/")
    if not findings:
        print("  PASS  no findings (correct)")
        passed += 1
    else:
        print(f"  FAIL  unexpected findings: {findings}")
        failed += 1

    # --- Test 4: individual function checks ---
    print("[TEST 4] Unit checks on is_misconfigured()")
    checks = [
        # (acao, acac, origin, expected)
        ("https://evil.com", "true", "https://evil.com", True),
        ("*", "true", "https://evil.com", True),
        ("https://evil.com", "false", "https://evil.com", False),
        ("", "true", "https://evil.com", False),
        ("https://good.com", "true", "https://evil.com", False),
    ]
    all_unit_ok = True
    for acao, acac, origin, expected in checks:
        result = is_misconfigured(acao, acac, origin)
        if result != expected:
            print(f"  FAIL  is_misconfigured({acao!r}, {acac!r}, {origin!r}) = {result}, expected {expected}")
            all_unit_ok = False
    if all_unit_ok:
        print("  PASS  all 5 unit checks passed")
        passed += 1
    else:
        failed += 1

    print()
    print("-" * 60)
    print(f"  Results: {passed} passed, {failed} failed")
    print("-" * 60)

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
