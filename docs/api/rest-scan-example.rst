Full REST API Workflow
======================

Configuration
-------------

API_TOKEN is configured in `.env` (see :ref:`Configuration <configuration>`).

Adding a Scan
-------------

.. code-block:: bash

    curl -X POST http://localhost:5000/api/add \
      -H "X-Api-Token: $API_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "enabled_modules": ["mail_dns_scanner"],
        "targets": ["example.com"]
      }'

Response:
.. code-block:: json

    {"scan_id": "abc123"}

Check Scan Status
-----------------

.. code-block:: bash

    curl -H "X-Api-Token: $API_TOKEN" \
      http://localhost:5000/api/scans/abc123

Get Report
----------

.. code-block:: bash

    curl -H "X-Api-Token: $API_TOKEN" \
      http://localhost:5000/api/scans/abc123/report/html \
      -o report.html
