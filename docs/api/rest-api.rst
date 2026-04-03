.. _rest-api:

REST API Guide
==============

Artemis exposes a REST API for programmatic interaction, allowing you to automate scanning workflows such as adding targets, monitoring progress, retrieving results, and exporting reports.

All API endpoints are prefixed with ``/api`` and require authentication via an API token. Interactive API documentation (Swagger UI) is also available at ``/docs`` on your Artemis instance.

Authentication
--------------

To use the API, set the ``API_TOKEN`` variable in your ``.env`` file (see :doc:`/user-guide/configuration` for details on configuration). All API requests must include this token in the ``X-API-Token`` header.

Requests with a missing or invalid token will receive a ``401`` response:

.. code-block:: bash

   curl -s http://localhost:5000/api/analyses \
      -H "X-API-Token: invalid-token"
   {"detail":"Invalid API token"}

Workflow: Adding and Monitoring a Scan
--------------------------------------

This section walks through the typical API workflow: adding targets, monitoring scan progress, and retrieving results.

Step 1: Add targets to scan
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use ``POST /api/add`` to submit targets for scanning.

.. code-block:: bash

   curl -s -X POST http://localhost:5000/api/add \
      -H "Content-Type: application/json" \
      -H "X-API-Token: YOUR_API_TOKEN" \
      -d '{
         "targets": ["example.com", "example.org"],
         "tag": "monthly-scan-2025-01"
      }'

Response:

.. code-block:: json

   {"ok": true, "ids": ["aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "ffffffff-1111-2222-3333-444444444444"]}

The ``ids`` field contains the analysis IDs for each submitted target. Save these to track progress.

**Parameters:**

- ``targets`` *(required, list of strings)* -- Domains, IPs, IP ranges, or ``host:port`` entries to scan.
- ``tag`` *(optional, string)* -- A label to group and filter results.
- ``disabled_modules`` *(optional, list of strings)* -- Module names to skip during scanning.
- ``enabled_modules`` *(optional, list of strings)* -- If provided, only these modules will run. Cannot be combined with ``disabled_modules``.
- ``priority`` *(optional, string)* -- Task priority: ``"low"``, ``"normal"`` (default), or ``"high"``.
- ``requests_per_second_override`` *(optional, float)* -- Override the per-target rate limit.
- ``module_runtime_configurations`` *(optional, object)* -- Per-module runtime configuration overrides.

.. note::

   Providing both ``disabled_modules`` and ``enabled_modules`` will result in a ``400`` error.

Step 2: List analyses
^^^^^^^^^^^^^^^^^^^^^

Use ``GET /api/analyses`` to list all analyses (scanned targets).

.. code-block:: bash

   curl -s http://localhost:5000/api/analyses \
      -H "X-API-Token: YOUR_API_TOKEN"

Response:

.. code-block:: json

   [
      {
         "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
         "target": "example.com",
         "tag": "monthly-scan-2025-01",
         "created_at": "2025-01-15T10:30:00",
         "stopped": false,
         "num_pending_tasks": 5,
         "disabled_modules": []
      }
   ]

Step 3: Monitor queue
^^^^^^^^^^^^^^^^^^^^^

Use ``GET /api/num-queued-tasks`` to check how many tasks are still waiting to be processed.

.. code-block:: bash

   curl -s http://localhost:5000/api/num-queued-tasks \
      -H "X-API-Token: YOUR_API_TOKEN"

Response:

.. code-block:: text

   23

The response is a plain integer. When it reaches ``0``, all tasks have been picked up by modules (though some may still be in progress).

You can also filter by specific module names:

.. code-block:: bash

   curl -s "http://localhost:5000/api/num-queued-tasks?karton_names=nuclei&karton_names=bruter" \
      -H "X-API-Token: YOUR_API_TOKEN"

Step 4: Retrieve results
^^^^^^^^^^^^^^^^^^^^^^^^

Use ``GET /api/task-results`` to fetch scanning results.

.. code-block:: bash

   curl -s "http://localhost:5000/api/task-results?only_interesting=true" \
      -H "X-API-Token: YOUR_API_TOKEN"

Response:

.. code-block:: json

   [
      {
         "id": "result-uuid",
         "created_at": "2025-01-15T10:35:00",
         "tag": "monthly-scan-2025-01",
         "receiver": "nuclei",
         "target_string": "example.com",
         "status": "INTERESTING",
         "status_reason": "Found vulnerability: ...",
         "analysis_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
         "task": {},
         "result": {},
         "logs": null,
         "additional_info": null
      }
   ]

**Query parameters:**

- ``only_interesting`` *(bool, default: true)* -- If ``true``, return only results with ``INTERESTING`` status (i.e. findings found by scanning modules).
- ``page`` *(int, default: 1)* -- Page number for pagination.
- ``page_size`` *(int, default: 100)* -- Number of results per page.
- ``analysis_id`` *(string, optional)* -- Filter results by a specific analysis.
- ``search`` *(string, optional)* -- Search results by keyword.

Step 5: Stop and delete an analysis
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use ``POST /api/stop-and-delete-analysis`` to cancel a running scan and remove its data.

.. code-block:: bash

   curl -s -X POST http://localhost:5000/api/stop-and-delete-analysis \
      -H "Content-Type: application/json" \
      -H "X-API-Token: YOUR_API_TOKEN" \
      -d '{"analysis_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}'

Response:

.. code-block:: json

   {"ok": true}

Other Endpoints
---------------

Exporting reports
^^^^^^^^^^^^^^^^^

**Create an export** -- ``POST /api/export``

Generate human-readable reports from scan results:

.. code-block:: bash

   curl -s -X POST http://localhost:5000/api/export \
      -H "Content-Type: application/json" \
      -H "X-API-Token: YOUR_API_TOKEN" \
      -d '{
            "language": "en_US",
            "skip_previously_exported": true,
            "tag": "monthly-scan-2025-01"
      }'

Response:

.. code-block:: json

   {"ok": true}

**List exports** -- ``GET /api/exports``

.. code-block:: bash

   curl -s http://localhost:5000/api/exports \
      -H "X-API-Token: YOUR_API_TOKEN"

Response:

.. code-block:: json

   [
      {
         "id": 1,
         "created_at": "2025-01-15T11:00:00",
         "comment": null,
         "tag": "monthly-scan-2025-01",
         "status": "done",
         "language": "en_US",
         "skip_previously_exported": true,
         "include_only_results_since": null,
         "zip_url": "/api/export/download-zip/1",
         "error": null,
         "alerts": null
      }
   ]

You can filter by tag prefix using the ``tag_prefix`` query parameter:

.. code-block:: bash

   curl -s "http://localhost:5000/api/exports?tag_prefix=monthly" \
      -H "X-API-Token: YOUR_API_TOKEN"

**Download an export** -- ``GET /api/export/download-zip/{id}``

.. code-block:: bash

   curl -s -L -o report.zip http://localhost:5000/api/export/download-zip/1 \
      -H "X-API-Token: YOUR_API_TOKEN"

**Delete an export** -- ``POST /api/export/delete/{id}``

.. code-block:: bash

   curl -s -X POST http://localhost:5000/api/export/delete/1 \
      -H "X-API-Token: YOUR_API_TOKEN"

Response:

.. code-block:: json

   {"ok": true}

Archiving tags
^^^^^^^^^^^^^^

Use ``POST /api/archive-tag`` to archive all data associated with a tag:

.. code-block:: bash

   curl -s -X POST http://localhost:5000/api/archive-tag \
      -H "Content-Type: application/json" \
      -H "X-API-Token: YOUR_API_TOKEN" \
      -d '{"tag": "monthly-scan-2025-01"}'

Response:

.. code-block:: json

   {"ok": true}

Checking the blocklist
^^^^^^^^^^^^^^^^^^^^^^

Use ``GET /api/is-blocklisted/{domain}`` to check whether scanning of a domain is blocked:

.. code-block:: bash

   curl -s http://localhost:5000/api/is-blocklisted/example.com \
      -H "X-API-Token: YOUR_API_TOKEN"

Response:

.. code-block:: json

   false

Rendering HTML messages
^^^^^^^^^^^^^^^^^^^^^^^

Use ``POST /api/build-html-message`` to render a custom list of vulnerabilities as HTML:

.. code-block:: bash

   curl -s -X POST http://localhost:5000/api/build-html-message \
      -H "Content-Type: application/json" \
      -H "X-API-Token: YOUR_API_TOKEN" \
      -d '{"language": "en_US", "data": {}}'

Complete Example: Automated Monthly Scan
----------------------------------------

The following shell script demonstrates a complete scanning workflow using the REST API:

.. code-block:: bash

   #!/bin/bash
   set -e

   ARTEMIS_URL="http://localhost:5000"
   API_TOKEN="YOUR_API_TOKEN"
   TAG="monthly-scan-$(date +%Y-%m)"

   # Step 1: Submit targets
   echo "Submitting targets..."
   RESPONSE=$(curl -s -X POST "$ARTEMIS_URL/api/add" \
         -H "Content-Type: application/json" \
         -H "X-API-Token: $API_TOKEN" \
         -d "{
            \"targets\": [\"example.com\", \"example.org\"],
            \"tag\": \"$TAG\"
         }")
   echo "Response: $RESPONSE"

   # Step 2: Wait for scanning to complete
   echo "Waiting for scan to complete..."
   while true; do
      QUEUED=$(curl -s "$ARTEMIS_URL/api/num-queued-tasks" \
         -H "X-API-Token: $API_TOKEN")
      echo "Queued tasks: $QUEUED"
      if [ "$QUEUED" -eq 0 ]; then
         break
      fi
      sleep 30
   done

   # Step 3: Retrieve interesting results
   echo "Fetching results..."
   curl -s "$ARTEMIS_URL/api/task-results?only_interesting=true" \
      -H "X-API-Token: $API_TOKEN" | python3 -m json.tool

   # Step 4: Generate and download a report
   echo "Creating export..."
   curl -s -X POST "$ARTEMIS_URL/api/export" \
      -H "Content-Type: application/json" \
      -H "X-API-Token: $API_TOKEN" \
      -d "{
         \"language\": \"en_US\",
         \"skip_previously_exported\": true,
         \"tag\": \"$TAG\"
      }"

   # Wait for the export to be ready
   while true; do
      EXPORTS=$(curl -s "$ARTEMIS_URL/api/exports?tag_prefix=$TAG" \
         -H "X-API-Token: $API_TOKEN")
      ZIP_URL=$(echo "$EXPORTS" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data[0].get('zip_url', '') if data else '')")
      if [ -n "$ZIP_URL" ]; then
         break
      fi
      sleep 10
   done

   # Download the report
   echo "Downloading report..."
   curl -s -L -o "report-$TAG.zip" "$ARTEMIS_URL$ZIP_URL" \
      -H "X-API-Token: $API_TOKEN"
   echo "Report saved to report-$TAG.zip"
