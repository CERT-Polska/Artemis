REST Scan API Example
=====================

To use Artemis REST API:

1. Start Artemis: `docker compose up -d`
2. Access Swagger UI: http://localhost:5000/docs
3. Key endpoints:

**Create scan:**
.. code-block:: bash

   curl -X POST http://localhost:5000/api/scans \\
     -H "Content-Type: application/json" \\
     -d '{"target": "example.com"}'

**List scans:**
.. code-block:: bash

   curl http://localhost:5000/api/scans

**Swagger docs:** http://localhost:5000/docs (full API)
