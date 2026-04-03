"""Integration tests validating the REST API workflow documented in docs/api/rest-api.rst.

These tests exercise the complete scan lifecycle through the API to ensure
the documented examples work against a running Artemis instance.
"""

import time
from test.e2e.base import BACKEND_URL, BaseE2ETestCase

import requests

API_TOKEN = "api-token"
HEADERS = {"X-API-Token": API_TOKEN}


class RestApiDocsTestCase(BaseE2ETestCase):
    """Test the REST API workflow as documented in rest-api.rst."""

    def test_full_scan_workflow_via_api(self) -> None:
        """Test the complete documented workflow: add targets, check analyses,
        monitor queue, retrieve results, and delete the analysis."""

        # Step 1: POST /api/add - Add a target to scan
        add_response = requests.post(
            BACKEND_URL + "api/add",
            json={
                "targets": ["test-smtp-server.artemis"],
                "tag": "rest-api-docs-test",
            },
            headers=HEADERS,
        )
        self.assertEqual(add_response.status_code, 200)
        add_data = add_response.json()
        self.assertTrue(add_data.get("ok"))
        self.assertIn("ids", add_data)
        self.assertEqual(len(add_data["ids"]), 1)
        analysis_id = add_data["ids"][0]

        # Step 2: GET /api/analyses - List analyses and verify ours exists
        analyses_response = requests.get(
            BACKEND_URL + "api/analyses",
            headers=HEADERS,
        )
        self.assertEqual(analyses_response.status_code, 200)
        analyses = analyses_response.json()
        self.assertEqual(len(analyses), 1)

        self.assertEqual(
            set(analyses[0].keys()),
            {"stopped", "target", "created_at", "id", "tag", "num_pending_tasks", "disabled_modules"},
        )
        self.assertEqual(analyses[0]["id"], analysis_id)
        self.assertEqual(analyses[0]["target"], "test-smtp-server.artemis")
        self.assertEqual(analyses[0]["tag"], "rest-api-docs-test")

        # Step 3: GET /api/num-queued-tasks - Check queue
        queue_response = requests.get(
            BACKEND_URL + "api/num-queued-tasks",
            headers=HEADERS,
        )
        self.assertEqual(queue_response.status_code, 200)
        num_queued = int(queue_response.content.strip())
        self.assertGreaterEqual(num_queued, 0)

        # Step 4: GET /api/task-results - Wait for and retrieve results
        for i in range(100):
            results_response = requests.get(
                BACKEND_URL + "api/task-results",
                params={"only_interesting": "false", "analysis_id": analysis_id},
                headers=HEADERS,
            )
            self.assertEqual(results_response.status_code, 200)
            task_results = results_response.json()

            if len(task_results) >= 1:
                break

            time.sleep(1)

        self.assertGreaterEqual(len(task_results), 1)
        self.assertEqual(
            set(task_results[0].keys()),
            {
                "created_at",
                "receiver",
                "status_reason",
                "task",
                "status",
                "analysis_id",
                "id",
                "tag",
                "target_string",
                "result",
                "logs",
                "additional_info",
            },
        )

        # Verify search filtering
        search_response = requests.get(
            BACKEND_URL + "api/task-results",
            params={"search": "nonexistent-search-term-xyz"},
            headers=HEADERS,
        )
        self.assertEqual(search_response.status_code, 200)
        self.assertEqual(len(search_response.json()), 0)

        # Verify pagination
        page_response = requests.get(
            BACKEND_URL + "api/task-results",
            params={"only_interesting": "false", "page": "1", "page_size": "1"},
            headers=HEADERS,
        )
        self.assertEqual(page_response.status_code, 200)
        self.assertLessEqual(len(page_response.json()), 1)

        # Wait for tasks to settle before cleanup
        time.sleep(20)

        # Step 5: POST /api/stop-and-delete-analysis - Clean up
        delete_response = requests.post(
            BACKEND_URL + "api/stop-and-delete-analysis",
            json={"analysis_id": analysis_id},
            headers=HEADERS,
        )
        self.assertEqual(delete_response.status_code, 200)
        self.assertEqual(delete_response.json(), {"ok": True})

        # Verify analysis is gone
        analyses_after = requests.get(BACKEND_URL + "api/analyses", headers=HEADERS).json()
        self.assertFalse(any(a["id"] == analysis_id for a in analyses_after))

    def test_api_add_with_enabled_modules(self) -> None:
        """Test POST /api/add with the enabled_modules parameter."""
        response = requests.post(
            BACKEND_URL + "api/add",
            json={
                "targets": ["test-smtp-server.artemis"],
                "tag": "rest-api-docs-enabled",
                "enabled_modules": ["mail_dns_scanner"],
            },
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("ok"))

    def test_api_add_rejects_both_enabled_and_disabled(self) -> None:
        """Test that POST /api/add rejects both enabled_modules and disabled_modules."""
        response = requests.post(
            BACKEND_URL + "api/add",
            json={
                "targets": ["test-smtp-server.artemis"],
                "disabled_modules": ["port_scanner"],
                "enabled_modules": ["mail_dns_scanner"],
            },
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 400)

    def test_api_is_blocklisted(self) -> None:
        """Test GET /api/is-blocklisted/{domain}."""
        response = requests.get(
            BACKEND_URL + "api/is-blocklisted/example.com",
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(response.json(), [True, False])

    def test_api_exports_empty(self) -> None:
        """Test GET /api/exports returns empty list when no exports exist."""
        response = requests.get(
            BACKEND_URL + "api/exports",
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_api_archive_tag(self) -> None:
        """Test POST /api/archive-tag."""
        response = requests.post(
            BACKEND_URL + "api/archive-tag",
            json={"tag": "nonexistent-tag"},
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})
