"""E2E tests for the REST API.

Tests the complete REST API workflow: adding targets, listing analyses,
checking queued tasks, retrieving results, creating exports, and managing analyses.
These tests call the live API directly and should break when the API code changes.
"""

import time
from test.e2e.base import BACKEND_URL, BaseE2ETestCase

import requests

API_TOKEN = "api-token"
HEADERS = {"X-API-Token": API_TOKEN, "Content-Type": "application/json"}
AUTH_HEADER = {"X-API-Token": API_TOKEN}
REQUEST_TIMEOUT = 10


def api_request(
    method: str,
    path: str,
    headers: dict = AUTH_HEADER,
    json: dict = None,
    params: dict = None,
    retries: int = 3,
) -> requests.Response:
    """Make an API request with retries to handle transient connection issues."""
    last_exc = None
    for attempt in range(retries):
        try:
            response = requests.request(
                method,
                BACKEND_URL + path,
                headers=headers,
                json=json,
                params=params,
                timeout=REQUEST_TIMEOUT,
            )
            return response
        except requests.exceptions.ConnectionError as e:
            last_exc = e
            time.sleep(2)
    raise last_exc  # type: ignore


class RestApiTestCase(BaseE2ETestCase):
    """Test the REST API endpoints directly."""

    def test_scan_workflow(self) -> None:
        """Test the complete scan workflow: add targets -> list analyses -> check queue -> get results."""
        # Step 1: Add targets
        response = api_request("POST", "api/add", headers=HEADERS, json={"targets": ["example.com"]})
        self.assertEqual(response.status_code, 200, f"POST /api/add failed: {response.text}")
        result = response.json()
        self.assertTrue(result.get("ok"), f"POST /api/add did not return ok: {result}")
        self.assertIn("ids", result)
        self.assertEqual(len(result["ids"]), 1)

        # Step 2: List analyses
        response = api_request("GET", "api/analyses")
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
        response = api_request("GET", "api/num-queued-tasks")
        self.assertEqual(response.status_code, 200, f"GET /api/num-queued-tasks failed: {response.text}")
        num_tasks = int(response.content.strip())
        self.assertGreaterEqual(num_tasks, 0)

        # Step 4: Get task results
        response = api_request("GET", "api/task-results")
        self.assertEqual(response.status_code, 200, f"GET /api/task-results failed: {response.text}")
        task_results = response.json()
        self.assertIsInstance(task_results, list)

    def test_add_targets_with_options(self) -> None:
        """Test adding targets with optional parameters (tag, disabled_modules)."""
        response = api_request(
            "POST",
            "api/add",
            headers=HEADERS,
            json={
                "targets": ["example.com"],
                "tag": "test-scan",
                "disabled_modules": ["port_scanner"],
            },
        )
        self.assertEqual(response.status_code, 200, f"POST /api/add with options failed: {response.text}")
        result = response.json()
        self.assertTrue(result.get("ok"), f"POST /api/add with options did not return ok: {result}")
        self.assertIn("ids", result)

    def test_export_workflow(self) -> None:
        """Test the export workflow: create export -> list exports."""
        # First add a target so there's something to export
        api_request("POST", "api/add", headers=HEADERS, json={"targets": ["example.com"]})

        # Create export
        response = api_request(
            "POST", "api/export", headers=HEADERS, json={"language": "en_US", "skip_previously_exported": False}
        )
        self.assertEqual(response.status_code, 200, f"POST /api/export failed: {response.text}")
        self.assertEqual(response.json(), {"ok": True})

        # List exports
        response = api_request("GET", "api/exports")
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
        response = api_request("GET", "api/is-blocklisted/example.com")
        self.assertEqual(response.status_code, 200, f"GET /api/is-blocklisted failed: {response.text}")
        self.assertIn(response.json(), [True, False])

    def test_stop_and_delete_analysis(self) -> None:
        """Test stopping and deleting an analysis."""
        # Create an analysis
        response = api_request("POST", "api/add", headers=HEADERS, json={"targets": ["example.com"]})
        self.assertEqual(response.status_code, 200)
        analysis_id = response.json()["ids"][0]

        # Verify it exists
        analyses = api_request("GET", "api/analyses").json()
        self.assertTrue(any(a["id"] == analysis_id for a in analyses))

        # Stop and delete (analysis_id is a query parameter in the FastAPI endpoint)
        response = api_request("POST", "api/stop-and-delete-analysis", params={"analysis_id": analysis_id})
        self.assertEqual(response.status_code, 200, f"POST /api/stop-and-delete-analysis failed: {response.text}")
        self.assertEqual(response.json(), {"ok": True})

        # Verify it's gone
        analyses = api_request("GET", "api/analyses").json()
        self.assertFalse(any(a["id"] == analysis_id for a in analyses))

    def test_api_token_required(self) -> None:
        """Verify that API endpoints return 401 without a valid token."""
        invalid_headers = {"X-API-Token": "invalid-token", "Content-Type": "application/json"}
        endpoints = [
            ("POST", "api/add", {"targets": ["example.com"]}),
            ("GET", "api/analyses", None),
            ("GET", "api/num-queued-tasks", None),
            ("GET", "api/task-results", None),
            ("GET", "api/exports", None),
            ("GET", "api/is-blocklisted/example.com", None),
        ]

        for method, path, json_data in endpoints:
            response = api_request(method, path, headers=invalid_headers, json=json_data)
            self.assertEqual(
                response.status_code,
                401,
                f"{method} /{path} should return 401 with invalid token, got {response.status_code}",
            )
