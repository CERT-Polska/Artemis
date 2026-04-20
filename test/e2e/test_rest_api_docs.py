"""Integration tests that extract and execute curl commands from docs/api/rest-api.rst.

Code blocks in the RST are annotated with ``.. test-id:: <label>`` comments.
These tests parse the RST, extract the labeled curl commands, convert them to
Python ``requests`` calls, and execute them against a running Artemis instance.
This ensures the documented examples stay in sync with the actual API.
"""

import json
import re
from test.e2e.base import BACKEND_URL, BaseE2ETestCase
from typing import Any, Dict, Optional
from urllib.parse import urlparse, urlunparse

import requests

API_TOKEN = "api-token"
RST_PATH = "/opt/docs/api/rest-api.rst"

STATIC_PLACEHOLDERS = {
    "http://localhost:5000": BACKEND_URL.rstrip("/"),
    "YOUR_API_TOKEN": API_TOKEN,
    "example.com": "test-smtp-server.artemis",
    "example.org": "test-smtp-server.artemis",
    "monthly-scan-2025-01": "rest-api-docs-test",
}


def extract_curl_blocks(rst_path: str) -> Dict[str, str]:
    """Extract labeled curl code blocks from the RST documentation.

    Looks for ``test-id:: <id>`` comments followed by ``.. code-block:: bash``
    directives and returns a mapping of test-id to the extracted curl command.
    """
    with open(rst_path) as f:
        content = f.read()

    pattern = r"test-id:: (\S+)\s*\n\s*\n\.\. code-block:: bash\s*\n\n((?:   [^\n]*\n)*)"
    blocks: Dict[str, str] = {}
    for match in re.finditer(pattern, content):
        test_id = match.group(1)
        code = match.group(2)
        # Strip RST's 3-space indentation
        lines = [line[3:] if line.startswith("   ") else line for line in code.rstrip("\n").split("\n")]
        blocks[test_id] = "\n".join(lines)
    return blocks


def parse_curl(command: str) -> Dict[str, Any]:
    """Parse a curl command string into structured request data."""
    # Join continuation lines
    command = command.replace("\\\n", " ")
    # Collapse whitespace (but preserve whitespace inside quotes)
    command = " ".join(command.split())

    result: Dict[str, Any] = {
        "method": "GET",
        "url": "",
        "headers": {},
        "json_body": None,
    }

    # Extract method (-X POST)
    m = re.search(r"-X\s+(\w+)", command)
    if m:
        result["method"] = m.group(1)

    # Extract headers (-H "Key: Value")
    for m in re.finditer(r'-H\s+"([^"]+)"', command):
        key, _, value = m.group(1).partition(": ")
        result["headers"][key] = value

    # Extract JSON body (-d '{...}')
    m = re.search(r"-d\s+'(\{.*?\})'", command, re.DOTALL)
    if m:
        result["json_body"] = json.loads(m.group(1))
        if result["method"] == "GET":
            result["method"] = "POST"

    # Extract URL (quoted or unquoted, starts with http)
    for m in re.finditer(r'"(http[^"]+)"|(?<!\w)(http\S+)', command):
        url = m.group(1) or m.group(2)
        if url:
            result["url"] = url
            break

    return result


def apply_placeholders(parsed: Dict[str, Any], dynamic: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Replace placeholder values in a parsed curl command with test values."""
    replacements = dict(STATIC_PLACEHOLDERS)
    if dynamic:
        replacements.update(dynamic)

    def replace_in_str(s: str) -> str:
        for old, new in replacements.items():
            s = s.replace(old, new)
        return s

    result = dict(parsed)
    result["url"] = replace_in_str(result["url"])
    result["headers"] = {k: replace_in_str(v) for k, v in result["headers"].items()}
    if result["json_body"]:
        body_str = replace_in_str(json.dumps(result["json_body"]))
        result["json_body"] = json.loads(body_str)
    return result


def execute_parsed_curl(parsed: Dict[str, Any]) -> requests.Response:
    """Execute a parsed curl command using the requests library."""
    kwargs: Dict[str, Any] = {"headers": parsed["headers"]}
    if parsed["json_body"]:
        kwargs["json"] = parsed["json_body"]
    return requests.request(parsed["method"], parsed["url"], **kwargs)


class RestApiDocsTestCase(BaseE2ETestCase):
    """Test the REST API by extracting and running curl commands from the documentation."""

    curl_blocks: Dict[str, str] = {}

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.curl_blocks = extract_curl_blocks(RST_PATH)
        assert len(cls.curl_blocks) >= 10, (
            f"Expected at least 10 annotated curl blocks in {RST_PATH}, "
            f"found {len(cls.curl_blocks)}: {list(cls.curl_blocks.keys())}"
        )

    def _extract_and_execute(self, test_id: str, dynamic: Optional[Dict[str, str]] = None) -> requests.Response:
        """Extract a labeled curl block from the docs, parse, substitute placeholders, and execute."""
        self.assertIn(test_id, self.curl_blocks, f"No curl block with test-id '{test_id}' found in docs")
        raw_curl = self.curl_blocks[test_id]
        parsed = parse_curl(raw_curl)
        parsed = apply_placeholders(parsed, dynamic)
        return execute_parsed_curl(parsed)

    def test_full_scan_workflow_via_api(self) -> None:
        """Test the complete documented workflow by extracting and running
        curl commands from Steps 1-5 in the docs."""

        # Step 1: POST /api/add - Add a target to scan
        add_response = self._extract_and_execute("step1-add")
        self.assertEqual(add_response.status_code, 200)
        add_data = add_response.json()
        self.assertTrue(add_data.get("ok"))
        self.assertIn("ids", add_data)
        self.assertGreaterEqual(len(add_data["ids"]), 1)

        analysis_id = add_data["ids"][0]
        dynamic = {"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee": analysis_id}

        # Step 2: GET /api/analyses - List analyses and verify ours exists
        analyses_response = self._extract_and_execute("step2-list-analyses", dynamic)
        self.assertEqual(analyses_response.status_code, 200)
        analyses = analyses_response.json()
        self.assertGreaterEqual(len(analyses), 1)
        self.assertEqual(
            set(analyses[0].keys()),
            {"stopped", "target", "created_at", "id", "tag", "num_pending_tasks", "disabled_modules"},
        )

        # Step 3: GET /api/num-queued-tasks - Check queue
        queue_response = self._extract_and_execute("step3-num-queued-tasks", dynamic)
        self.assertEqual(queue_response.status_code, 200)
        num_queued = int(queue_response.content.strip())
        self.assertGreaterEqual(num_queued, 0)

        # Step 3b: GET /api/num-queued-tasks with filter
        filtered_response = self._extract_and_execute("step3-num-queued-tasks-filtered", dynamic)
        self.assertEqual(filtered_response.status_code, 200)

        # Wait for all scanning modules to finish processing before querying results.
        self.wait_for_tasks_finished()

        # Step 4: GET /api/task-results - Retrieve results
        # The docs show only_interesting=true, but we use only_interesting=false
        # to find all results from our test scan. Since setUp cleans the DB,
        # all results belong to this test.
        parsed = parse_curl(self.curl_blocks["step4-task-results"])
        parsed = apply_placeholders(parsed, dynamic)
        url_parts = urlparse(parsed["url"])
        parsed["url"] = urlunparse(url_parts._replace(query="only_interesting=false"))

        results_response = execute_parsed_curl(parsed)
        self.assertEqual(results_response.status_code, 200)
        task_results = results_response.json()

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

        # Step 5: POST /api/stop-and-delete-analysis - Clean up
        delete_response = self._extract_and_execute("step5-stop-and-delete", dynamic)
        self.assertEqual(delete_response.status_code, 200)
        self.assertEqual(delete_response.json(), {"ok": True})

        # Verify the deleted analysis is gone
        analyses_after = self._extract_and_execute("step2-list-analyses", dynamic)
        remaining_ids = [a["id"] for a in analyses_after.json()]
        self.assertNotIn(analysis_id, remaining_ids)

    def test_api_add_rejects_both_enabled_and_disabled(self) -> None:
        """Test that POST /api/add rejects both enabled_modules and disabled_modules.
        This is an error case not documented in the guide, so it stays as a manual test."""
        response = requests.post(
            BACKEND_URL + "api/add",
            json={
                "targets": ["test-smtp-server.artemis"],
                "disabled_modules": ["port_scanner"],
                "enabled_modules": ["mail_dns_scanner"],
            },
            headers={"X-API-Token": API_TOKEN},
        )
        self.assertEqual(response.status_code, 400)

    def test_api_is_blocklisted(self) -> None:
        """Test GET /api/is-blocklisted/{domain} using the documented curl command."""
        response = self._extract_and_execute("is-blocklisted")
        self.assertEqual(response.status_code, 200)
        self.assertIn(response.json(), [True, False])

    def test_api_exports_empty(self) -> None:
        """Test GET /api/exports returns empty list when no exports exist."""
        response = self._extract_and_execute("exports-list")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_api_archive_tag(self) -> None:
        """Test POST /api/archive-tag using the documented curl command."""
        response = self._extract_and_execute("archive-tag")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})

    def test_api_build_html_message(self) -> None:
        """Test POST /api/build-html-message using the documented curl command.
        This endpoint proxies to the autoreporter service, which may return 500
        if the service is unavailable in the test environment."""
        response = self._extract_and_execute("build-html-message")
        self.assertIn(response.status_code, [200, 500])
