"""E2E tests for the REST API.

Tests the complete REST API workflow: adding targets, listing analyses,
checking queued tasks, retrieving results, creating exports, and managing analyses.
These tests call the live API directly and should break when the API code changes.
"""

from test.e2e.base import BACKEND_URL, BaseE2ETestCase

import requests

API_TOKEN = "api-token"
HEADERS = {"X-API-Token": API_TOKEN, "Content-Type": "application/json"}
AUTH_HEADER = {"X-API-Token": API_TOKEN}


class RestApiTestCase(BaseE2ETestCase):
    """Test the REST API endpoints directly."""

    def test_scan_workflow(self) -> None:
        """Test the complete scan workflow: add targets -> list analyses -> check queue -> get results."""
        # Step 1: Add targets
        response = requests.post(
            BACKEND_URL + "api/add",
            json={"targets": ["example.com"]},
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 200, f"POST /api/add failed: {response.text}")
        result = response.json()
        self.assertTrue(result.get("ok"), f"POST /api/add did not return ok: {result}")
        self.assertIn("ids", result)
        self.assertEqual(len(result["ids"]), 1)

        # Step 2: List analyses
        response = requests.get(
            BACKEND_URL + "api/analyses",
            headers=AUTH_HEADER,
        )
        self.assertEqual(response.status_code, 200, f"GET /api/analyses failed: {response.text}")
        analyses = response.json()
        self.assertIsInstance(analyses, list)
        self.assertGreaterEqual(len(analyses), 1)
        analysis = analyses[0]
        expected_keys = {"id", "target", "tag", "created_at", "stopped", "num_pending_tasks", "disabled_modules"}
        self.assertEqual(
            set(analysis.keys()),
            expected_keys,
            f"Unexpected analysis keys: {set(analysis.keys())}",
        )

        # Step 3: Check number of queued tasks
        response = requests.get(
            BACKEND_URL + "api/num-queued-tasks",
            headers=AUTH_HEADER,
        )
        self.assertEqual(response.status_code, 200, f"GET /api/num-queued-tasks failed: {response.text}")
        num_tasks = int(response.content.strip())
        self.assertGreaterEqual(num_tasks, 0)

        # Step 4: Get task results
        response = requests.get(
            BACKEND_URL + "api/task-results",
            headers=AUTH_HEADER,
        )
        self.assertEqual(response.status_code, 200, f"GET /api/task-results failed: {response.text}")
        task_results = response.json()
        self.assertIsInstance(task_results, list)

    def test_add_targets_with_options(self) -> None:
        """Test adding targets with optional parameters (tag, disabled_modules)."""
        response = requests.post(
            BACKEND_URL + "api/add",
            json={
                "targets": ["example.com"],
                "tag": "test-scan",
                "disabled_modules": ["port_scanner"],
            },
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 200, f"POST /api/add with options failed: {response.text}")
        result = response.json()
        self.assertTrue(result.get("ok"), f"POST /api/add with options did not return ok: {result}")
        self.assertIn("ids", result)

    def test_export_workflow(self) -> None:
        """Test the export workflow: create export -> list exports."""
        # First add a target so there's something to export
        requests.post(
            BACKEND_URL + "api/add",
            json={"targets": ["example.com"]},
            headers=HEADERS,
        )

        # Create export
        response = requests.post(
            BACKEND_URL + "api/export",
            json={"language": "en_US", "skip_previously_exported": False},
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 200, f"POST /api/export failed: {response.text}")
        self.assertEqual(response.json(), {"ok": True})

        # List exports
        response = requests.get(
            BACKEND_URL + "api/exports",
            headers=AUTH_HEADER,
        )
        self.assertEqual(response.status_code, 200, f"GET /api/exports failed: {response.text}")
        exports = response.json()
        self.assertIsInstance(exports, list)
        self.assertGreaterEqual(len(exports), 1)
        export_entry = exports[0]
        expected_export_keys = {
            "id",
            "created_at",
            "comment",
            "tag",
            "status",
            "language",
            "skip_previously_exported",
            "zip_url",
            "error",
            "alerts",
            "include_only_results_since",
        }
        self.assertEqual(
            set(export_entry.keys()),
            expected_export_keys,
            f"Unexpected export keys: {set(export_entry.keys())}",
        )

    def test_is_blocklisted(self) -> None:
        """Test the is-blocklisted endpoint."""
        response = requests.get(
            BACKEND_URL + "api/is-blocklisted/example.com",
            headers=AUTH_HEADER,
        )
        self.assertEqual(response.status_code, 200, f"GET /api/is-blocklisted failed: {response.text}")
        self.assertIn(response.json(), [True, False])

    def test_stop_and_delete_analysis(self) -> None:
        """Test stopping and deleting an analysis."""
        # Create an analysis
        response = requests.post(
            BACKEND_URL + "api/add",
            json={"targets": ["example.com"]},
            headers=HEADERS,
        )
        analysis_id = response.json()["ids"][0]

        # Verify it exists
        analyses = requests.get(BACKEND_URL + "api/analyses", headers=AUTH_HEADER).json()
        self.assertTrue(any(a["id"] == analysis_id for a in analyses))

        # Stop and delete
        response = requests.post(
            BACKEND_URL + "api/stop-and-delete-analysis",
            json={"analysis_id": analysis_id},
            headers=HEADERS,
        )
        self.assertEqual(response.status_code, 200, f"POST /api/stop-and-delete-analysis failed: {response.text}")
        self.assertEqual(response.json(), {"ok": True})

        # Verify it's gone
        analyses = requests.get(BACKEND_URL + "api/analyses", headers=AUTH_HEADER).json()
        self.assertFalse(any(a["id"] == analysis_id for a in analyses))

    def test_api_token_required(self) -> None:
        """Verify that API endpoints return 401 without a valid token."""
        endpoints = [
            ("POST", "api/add", {"targets": ["example.com"]}),
            ("GET", "api/analyses", None),
            ("GET", "api/num-queued-tasks", None),
            ("GET", "api/task-results", None),
            ("GET", "api/exports", None),
            ("GET", "api/is-blocklisted/example.com", None),
        ]

        for method, path, json_data in endpoints:
            response = requests.request(
                method,
                BACKEND_URL + path,
                json=json_data,
                headers={"X-API-Token": "invalid-token", "Content-Type": "application/json"},
            )
            self.assertEqual(
                response.status_code,
                401,
                f"{method} /{path} should return 401 with invalid token, got {response.status_code}",
            )
