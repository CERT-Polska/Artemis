Full REST API Workflow
======================

Configuration
-------------

API_TOKEN is configured in `.env` (see :ref:`Configuration <configuration>`).

Available modules shown in Web UI: Scans → New Scan → Modules panel.

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

**Real Response**:
.. code-block:: json

    {
      "id": "abc123",
      "status": "queued", 
      "targets": ["example.com"]
    }

Checking Scan Status
--------------------

.. code-block:: bash

    curl -H "X-Api-Token: $API_TOKEN" \
      http://localhost:5000/api/current_user/scans

Getting Report (when ready)
---------------------------

.. code-block:: bash

    curl -H "X-Api-Token: $API_TOKEN" \
      http://localhost:5000/api/current_user/scans/abc123/report/html \
      > report.html
