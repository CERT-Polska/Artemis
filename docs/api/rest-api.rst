.. _rest-api:

REST API
========

Artemis provides a REST API that allows you to automate scanning and report generation.
All API endpoints are served under the ``/api`` prefix and require authentication via an API token.

.. note::

   Swagger (OpenAPI) interactive documentation is also available at ``http://localhost:5000/docs``
   when the ``API_TOKEN`` is configured.


Authentication
--------------

All API requests must include the ``X-API-Token`` header with a valid token.

To enable the API, set the ``API_TOKEN`` variable in your ``.env`` file:

.. code-block:: bash

   API_TOKEN=my-secret-token

Every request must then include the header:

.. code-block:: none

   X-API-Token: my-secret-token

If the token is missing or invalid, the API returns HTTP 401.


Example workflow: adding a scan and retrieving results
------------------------------------------------------

Below is a complete example of how to use the REST API to:

1. Add targets to be scanned
2. List analyses to verify the scan was created
3. Check the number of queued tasks
4. Retrieve scan results

.. _rest-api-step-1:

Step 1: Add targets
^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # rest-api-add-targets
   curl -s -X POST http://localhost:5000/api/add \
     -H "Content-Type: application/json" \
     -H "X-API-Token: $API_TOKEN" \
     -d '{"targets": ["example.com"]}'

**Response:**

.. code-block:: json

   {"ok": true, "ids": ["<analysis-id>"]}

The ``targets`` field accepts domains, IPs, IP ranges (e.g. ``10.0.0.0/24`` or ``10.0.0.1-10.0.0.10``)
and ``host:port`` entries (in the latter case, no port scanning is performed).

You can also pass optional parameters:

- ``tag`` (string) - a label for the analysis
- ``disabled_modules`` (list of strings) - modules to disable for this scan
- ``enabled_modules`` (list of strings) - only enable these modules (mutually exclusive with ``disabled_modules``)
- ``priority`` (string) - task priority, default ``"normal"``
- ``requests_per_second_override`` (float) - rate limit override

Example with optional parameters:

.. code-block:: bash

   # rest-api-add-targets-with-options
   curl -s -X POST http://localhost:5000/api/add \
     -H "Content-Type: application/json" \
     -H "X-API-Token: $API_TOKEN" \
     -d '{
       "targets": ["example.com"],
       "tag": "monthly-scan",
       "priority": "normal"
     }'

.. _rest-api-step-2:

Step 2: List analyses
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # rest-api-list-analyses
   curl -s http://localhost:5000/api/analyses \
     -H "X-API-Token: $API_TOKEN"

**Response:**

.. code-block:: json

   [
     {
       "id": "<analysis-id>",
       "target": "example.com",
       "tag": "monthly-scan",
       "created_at": "2026-01-01T00:00:00",
       "stopped": false,
       "num_pending_tasks": 5,
       "disabled_modules": []
     }
   ]

.. _rest-api-step-3:

Step 3: Check queued tasks
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # rest-api-num-queued-tasks
   curl -s http://localhost:5000/api/num-queued-tasks \
     -H "X-API-Token: $API_TOKEN"

**Response:** a plain integer, e.g. ``5``.

Once this returns ``0``, all tasks have been processed.

.. _rest-api-step-4:

Step 4: Get task results
^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # rest-api-task-results
   curl -s "http://localhost:5000/api/task-results?only_interesting=true" \
     -H "X-API-Token: $API_TOKEN"

**Response:**

.. code-block:: json

   [
     {
       "id": "<result-id>",
       "analysis_id": "<analysis-id>",
       "tag": "monthly-scan",
       "target_string": "example.com",
       "receiver": "nuclei",
       "status": "INTERESTING",
       "status_reason": "Found problems: ...",
       "created_at": "2026-01-01T00:01:00",
       "result": {},
       "task": {},
       "logs": "",
       "additional_info": ""
     }
   ]

You can also filter results with query parameters:

- ``only_interesting`` (boolean, default ``true``) - show only interesting results
- ``page`` (integer, default ``1``) - page number
- ``page_size`` (integer, default ``100``) - number of results per page
- ``analysis_id`` (string) - filter by a specific analysis
- ``search`` (string) - search query


Example workflow: generating and downloading a report
-----------------------------------------------------

Once a scan is complete, you can generate a report export containing human-readable
HTML messages for each scanned entity.

Step 1: Create an export
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # rest-api-create-export
   curl -s -X POST http://localhost:5000/api/export \
     -H "Content-Type: application/json" \
     -H "X-API-Token: $API_TOKEN" \
     -d '{
       "language": "en_US",
       "skip_previously_exported": false,
       "tag": "monthly-scan",
       "comment": "March 2026 report"
     }'

**Response:**

.. code-block:: json

   {"ok": true}

Step 2: Check export status
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # rest-api-list-exports
   curl -s http://localhost:5000/api/exports \
     -H "X-API-Token: $API_TOKEN"

**Response:**

.. code-block:: json

   [
     {
       "id": 1,
       "created_at": "2026-01-01T00:05:00",
       "comment": "March 2026 report",
       "tag": "monthly-scan",
       "status": "done",
       "language": "en_US",
       "skip_previously_exported": false,
       "zip_url": "/api/export/download-zip/1",
       "error": null,
       "alerts": null,
       "include_only_results_since": null
     }
   ]

When ``status`` is ``"done"`` and ``zip_url`` is not ``null``, the export is ready to download.

Step 3: Download the export
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # rest-api-download-export
   curl -s -L -o report.zip http://localhost:5000/api/export/download-zip/1 \
     -H "X-API-Token: $API_TOKEN"

The downloaded ``.zip`` file contains HTML messages ready to be sent and additional data
such as statistics and raw JSON output.


Other API endpoints
-------------------

Stop and delete an analysis
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # rest-api-stop-analysis
   curl -s -X POST http://localhost:5000/api/stop-and-delete-analysis \
     -H "Content-Type: application/json" \
     -H "X-API-Token: $API_TOKEN" \
     -d '{"analysis_id": "<analysis-id>"}'

**Response:**

.. code-block:: json

   {"ok": true}

Check if a domain is blocklisted
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # rest-api-is-blocklisted
   curl -s http://localhost:5000/api/is-blocklisted/example.com \
     -H "X-API-Token: $API_TOKEN"

**Response:** ``true`` or ``false``.

Delete an export
^^^^^^^^^^^^^^^^

.. code-block:: bash

   # rest-api-delete-export
   curl -s -X POST http://localhost:5000/api/export/delete/1 \
     -H "X-API-Token: $API_TOKEN"

**Response:**

.. code-block:: json

   {"ok": true}
