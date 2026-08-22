# GSoC 2026 PoC — CORS Misconfiguration Scanner for Artemis

Proof-of-concept for the GSoC 2026 project **"Extending the Artemis Scanner"**.
This demonstrates how a new vulnerability detection module integrates into the
Artemis scanning framework end-to-end.

## What this PoC covers

**A complete, convention-matching CORS misconfiguration scanner module** that
follows every Artemis pattern exactly:

| Component | File |
|-----------|------|
| Scanning module | `artemis/modules/cors_scanner.py` |
| Reporter (finding → report) | `artemis/reporting/modules/cors_scanner/reporter.py` |
| Email template (Jinja2) | `artemis/reporting/modules/cors_scanner/template_cors_misconfiguration.jinja2` |
| Translations (en + pl) | `artemis/reporting/modules/cors_scanner/translations/` |
| Severity mapping | `artemis/reporting/severity.py` (one line added) |
| Docker service definition | `docker-compose.yaml` (service `karton-cors-scanner`) |
| Module test | `test/modules/test_cors_scanner.py` |
| Reporter integration test | `test/reporting/test_cors_scanner_autoreporter_integration.py` |
| Test target (vulnerable Flask app) | `test/data/cors_test_app/` |
| Test service definitions | `docker-compose.test.yaml` |
| Standalone verification script | `poc_cors_verify.py` |

## What the module detects

CORS misconfiguration (CWE-942) — when a server reflects arbitrary `Origin`
headers in its `Access-Control-Allow-Origin` response **and** sets
`Access-Control-Allow-Credentials: true`. This combination allows any external
website to make authenticated cross-origin requests and read the responses,
enabling cross-origin data theft.

The module tests three attack vectors:
1. **Arbitrary origin** (`https://evil.com`) — direct reflection check
2. **Null origin** (`null`) — sandboxed iframe / data URI bypass
3. **Suffix-match bypass** (`https://target.evil.com`) — regex misconfiguration

Only flagged when *both* reflection and credentials are present (minimizes false
positives).

## How to run the PoC locally

### Quick verification (no Docker/Redis/Postgres needed)

```bash
pip install flask requests
python poc_cors_verify.py
```

This starts an embedded test server with intentional CORS misconfigurations,
runs the core detection logic against it, and reports pass/fail:

```
============================================================
  Artemis CORS Scanner — PoC Verification
============================================================

[TEST 1] Vulnerable endpoint — reflected Origin + ACAC:true
  PASS  found 2 finding(s): ...
[TEST 2] Safe endpoint — ACAO:* without credentials
  PASS  no findings (correct)
[TEST 3] No CORS headers — default deny
  PASS  no findings (correct)
[TEST 4] Unit checks on is_misconfigured()
  PASS  all 5 unit checks passed

  Results: 4 passed, 0 failed
```

### Full integration (inside Artemis Docker stack)

```bash
# Start Artemis in development mode
./scripts/start --mode=development

# The cors_scanner module will auto-start as karton-cors-scanner service
# Submit a target via the web UI at http://localhost:5000 or via API:
curl -X POST http://localhost:5000/api/add \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com"]}'
```

### Run the module tests (requires test Docker stack)

```bash
./scripts/test
# Or specifically:
# unittest-parallel -j 4 -t . -s test.modules -k test_cors_scanner
```

## Core approach

The central idea: Artemis modules are Karton services that consume typed tasks
from a Redis queue, perform focused security checks, and save structured results
to PostgreSQL. Each module follows a strict contract:

1. **Inherit from `ArtemisBase`** — gets rate limiting, caching, locking, retry
2. **Declare `filters`** — which task types to consume (here: HTTP services)
3. **Implement `run()`** — the scanning logic
4. **Call `self.db.save_task_result()`** — persist findings with status + data
5. **Create a `Reporter` subclass** — convert raw results into `Report` objects
6. **Provide Jinja2 templates** — human-readable email messages for CSIRTs
7. **Register severity** — add to `severity.py` mapping
8. **Add Docker service** — one container per module in `docker-compose.yaml`

This PoC implements all 8 steps for the CORS scanner, showing the full module
lifecycle from task consumption through report generation.

## Files modified in existing codebase

Only two existing files were touched (minimal footprint):

- `artemis/reporting/severity.py` — added 1 line: `ReportType("cors_misconfiguration"): Severity.MEDIUM`
- `docker-compose.yaml` — added 6 lines: service definition for `karton-cors-scanner`
- `docker-compose.test.yaml` — added 9 lines: test service definitions
