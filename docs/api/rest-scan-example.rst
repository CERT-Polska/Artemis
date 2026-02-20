Adding Scans via REST API
=========================

Get your API token from user profile at: http://localhost:5000

Example:

.. code-block:: bash

    curl -X POST http://localhost:5000/api/add \
      -H "X-Api-Token: YOUR_API_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "enabled_modules": ["mail_dns_scanner"],
        "targets": ["example.com"]
      }'

Response includes scan ID. View results at: /scans/{scan_id}.
