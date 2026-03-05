import json
import re
from test.e2e.base import BACKEND_URL, BaseE2ETestCase
from typing import Any, Dict, Optional

import requests

API_TOKEN = "api-token"
DOCS_PATH = "docs/api/rest-api.rst"


def extract_curl_commands(filepath: str) -> Dict[str, str]:
    """Extract curl commands from the documentation, keyed by their comment identifier.

    Each curl command in the docs is preceded by a comment like:
        # rest-api-add-targets
    This function returns a dict mapping those identifiers to the curl command strings.
    """
    with open(filepath, "r") as f:
        content = f.read()

    commands: Dict[str, str] = {}
    # Match code blocks containing curl commands with their preceding comment identifiers
    # The pattern matches: "# <identifier>\n   curl ..." inside code-block:: bash sections
    pattern = r"# (rest-api-[\w-]+)\n\s+(curl\s+.*?)(?=\n\n|\n\.\.|$)"
    for match in re.finditer(pattern, content, re.DOTALL):
        identifier = match.group(1)
        curl_cmd = match.group(2).strip()
        # Join continuation lines (backslash at end of line)
        curl_cmd = re.sub(r"\\\n\s*", " ", curl_cmd)
        commands[identifier] = curl_cmd
    return commands


def run_curl_via_requests(
    curl_cmd: str, api_token: str, base_url: str, analysis_id: Optional[str] = None
) -> requests.Response:
    """Parse a curl command string and execute it using the requests library.

    Replaces $API_TOKEN with the actual token and localhost:5000 with the test backend URL.
    Replaces <analysis-id> with the real analysis ID if provided.
    """
    curl_cmd = curl_cmd.replace("$API_TOKEN", api_token)
    curl_cmd = curl_cmd.replace("http://localhost:5000/", base_url)
    if analysis_id:
        curl_cmd = curl_cmd.replace("<analysis-id>", analysis_id)

    # Determine method
    method = "GET"
    if "-X POST" in curl_cmd:
        method = "POST"
    elif "-X PUT" in curl_cmd:
        method = "PUT"
    elif "-X DELETE" in curl_cmd:
        method = "DELETE"

    # Extract URL
    url_match = re.search(r"(https?://\S+)", curl_cmd.replace('"', " ").replace("'", " "))
    if not url_match:
        raise ValueError(f"Could not extract URL from curl command: {curl_cmd}")
    url = url_match.group(1).rstrip("'\"")

    # Extract headers
    headers: Dict[str, str] = {}
    for header_match in re.finditer(r'-H\s+"([^"]+)"', curl_cmd):
        key, _, value = header_match.group(1).partition(": ")
        headers[key] = value
    for header_match in re.finditer(r"-H\s+'([^']+)'", curl_cmd):
        key, _, value = header_match.group(1).partition(": ")
        headers[key] = value

    # Extract JSON body
    json_data: Optional[Dict[str, Any]] = None
    data_match = re.search(r"-d\s+'(\{.*?\})'", curl_cmd, re.DOTALL)
    if data_match:
        json_data = json.loads(data_match.group(1))

    # Handle -L (follow redirects) and -o (output file) flags
    allow_redirects = "-L" in curl_cmd

    return requests.request(
        method,
        url,
        headers=headers,
        json=json_data,
        allow_redirects=allow_redirects,
    )


class RestApiDocExamplesTestCase(BaseE2ETestCase):
    """Test that the curl commands documented in docs/api/rest-api.rst actually work."""

    def test_documented_curl_commands_work(self) -> None:
        """Extract curl commands from the REST API docs and verify each one works against the live API."""
        commands = extract_curl_commands(DOCS_PATH)

        # Verify we extracted the expected commands
        expected_commands = [
            "rest-api-add-targets",
            "rest-api-add-targets-with-options",
            "rest-api-list-analyses",
            "rest-api-num-queued-tasks",
            "rest-api-task-results",
            "rest-api-create-export",
            "rest-api-list-exports",
            "rest-api-is-blocklisted",
        ]
        for cmd_id in expected_commands:
            self.assertIn(
                cmd_id,
                commands,
                f"Expected curl command '{cmd_id}' not found in docs. Found: {list(commands.keys())}",
            )

        # --- Step 1: Add targets ---
        response = run_curl_via_requests(commands["rest-api-add-targets"], API_TOKEN, BACKEND_URL)
        self.assertEqual(response.status_code, 200, f"POST /api/add failed: {response.text}")
        result = response.json()
        self.assertTrue(result.get("ok"), f"POST /api/add did not return ok: {result}")
        self.assertIn("ids", result)
        self.assertEqual(len(result["ids"]), 1)

        # --- Step 2: List analyses ---
        response = run_curl_via_requests(commands["rest-api-list-analyses"], API_TOKEN, BACKEND_URL)
        self.assertEqual(response.status_code, 200, f"GET /api/analyses failed: {response.text}")
        analyses = response.json()
        self.assertIsInstance(analyses, list)
        self.assertGreaterEqual(len(analyses), 1)
        # Verify the response has the documented keys
        analysis = analyses[0]
        expected_keys = {"id", "target", "tag", "created_at", "stopped", "num_pending_tasks", "disabled_modules"}
        self.assertEqual(set(analysis.keys()), expected_keys, f"Unexpected analysis keys: {set(analysis.keys())}")

        # --- Step 3: Check queued tasks ---
        response = run_curl_via_requests(commands["rest-api-num-queued-tasks"], API_TOKEN, BACKEND_URL)
        self.assertEqual(response.status_code, 200, f"GET /api/num-queued-tasks failed: {response.text}")
        # Response is a plain integer
        num_tasks = int(response.content.strip())
        self.assertGreaterEqual(num_tasks, 0)

        # --- Step 4: Get task results ---
        response = run_curl_via_requests(commands["rest-api-task-results"], API_TOKEN, BACKEND_URL)
        self.assertEqual(response.status_code, 200, f"GET /api/task-results failed: {response.text}")
        task_results = response.json()
        self.assertIsInstance(task_results, list)

        # --- Step 5: Add targets with options ---
        response = run_curl_via_requests(commands["rest-api-add-targets-with-options"], API_TOKEN, BACKEND_URL)
        self.assertEqual(response.status_code, 200, f"POST /api/add with options failed: {response.text}")
        result = response.json()
        self.assertTrue(result.get("ok"), f"POST /api/add with options did not return ok: {result}")

        # --- Step 6: Create export ---
        response = run_curl_via_requests(commands["rest-api-create-export"], API_TOKEN, BACKEND_URL)
        self.assertEqual(response.status_code, 200, f"POST /api/export failed: {response.text}")
        result = response.json()
        self.assertEqual(result, {"ok": True})

        # --- Step 7: List exports ---
        response = run_curl_via_requests(commands["rest-api-list-exports"], API_TOKEN, BACKEND_URL)
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

        # --- Step 8: Check blocklist ---
        response = run_curl_via_requests(commands["rest-api-is-blocklisted"], API_TOKEN, BACKEND_URL)
        self.assertEqual(response.status_code, 200, f"GET /api/is-blocklisted failed: {response.text}")
        # Response should be a boolean
        self.assertIn(response.json(), [True, False])

    def test_api_token_required_for_documented_endpoints(self) -> None:
        """Verify that all documented endpoints return 401 without a valid API token."""
        endpoints_to_check = [
            ("POST", "api/add", {"targets": ["example.com"]}),
            ("GET", "api/analyses", None),
            ("GET", "api/num-queued-tasks", None),
            ("GET", "api/task-results", None),
            ("GET", "api/exports", None),
            ("GET", "api/is-blocklisted/example.com", None),
        ]

        for method, path, json_data in endpoints_to_check:
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

    def test_stop_and_delete_analysis_documented_endpoint(self) -> None:
        """Test the documented stop-and-delete-analysis endpoint."""
        # First, create an analysis
        response = requests.post(
            BACKEND_URL + "api/add",
            json={"targets": ["example.com"]},
            headers={"X-API-Token": API_TOKEN, "Content-Type": "application/json"},
        )
        analysis_id = response.json()["ids"][0]

        # Verify analysis exists
        analyses = requests.get(
            BACKEND_URL + "api/analyses",
            headers={"X-API-Token": API_TOKEN},
        ).json()
        self.assertTrue(any(a["id"] == analysis_id for a in analyses))

        # Stop and delete it using the documented endpoint format
        commands = extract_curl_commands(DOCS_PATH)
        response = run_curl_via_requests(
            commands["rest-api-stop-analysis"], API_TOKEN, BACKEND_URL, analysis_id=analysis_id
        )
        self.assertEqual(response.status_code, 200, f"POST /api/stop-and-delete-analysis failed: {response.text}")
        self.assertEqual(response.json(), {"ok": True})

        # Verify analysis is deleted
        analyses = requests.get(
            BACKEND_URL + "api/analyses",
            headers={"X-API-Token": API_TOKEN},
        ).json()
        self.assertFalse(any(a["id"] == analysis_id for a in analyses))
