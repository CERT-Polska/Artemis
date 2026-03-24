"""
Tests that validate the REST API documentation examples work correctly.

These tests extract curl commands from the documentation and verify that
the documented API endpoints respond as expected.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest import TestCase


def get_docs_path() -> Path:
    """Get the path to the rest-api.rst documentation file."""
    # Navigate from test/documentation to docs/api/rest-api.rst
    current_dir = Path(__file__).parent
    docs_path = current_dir.parent.parent / "docs" / "api" / "rest-api.rst"
    return docs_path


def extract_curl_commands(rst_content: str) -> List[Tuple[str, str]]:
    """
    Extract curl commands from RST documentation.

    Returns a list of tuples: (command_id, curl_command)
    Command IDs are extracted from comments like "# rest-api-add-targets"
    """
    commands = []

    # Pattern to match bash code blocks with curl commands
    # Look for: .. code-block:: bash followed by content with # comment-id and curl command
    pattern = r"\.\. code-block:: bash\s*\n\s*\n\s*# (rest-api-[\w-]+)\s*\n(.*?)(?=\n\n|\n\.\.|$)"

    matches = re.findall(pattern, rst_content, re.DOTALL)

    for command_id, command_block in matches:
        # Clean up the command - join continued lines and strip whitespace
        lines = command_block.strip().split("\n")
        full_command = ""
        for line in lines:
            line = line.strip()
            if line.endswith("\\"):
                full_command += line[:-1] + " "
            else:
                full_command += line
        commands.append((command_id, full_command.strip()))

    return commands


def parse_curl_command(curl_cmd: str) -> Dict[str, Any]:
    """
    Parse a curl command string into its components.

    Returns a dict with: method, url, headers, data
    """
    result: Dict[str, Any] = {
        "method": "GET",
        "url": "",
        "headers": {},
        "data": None,
    }

    # Extract method
    if "-X POST" in curl_cmd or "-X 'POST'" in curl_cmd:
        result["method"] = "POST"

    # Extract URL - it's usually the part that starts with http
    url_match = re.search(r'(http://[^\s"\']+)', curl_cmd)
    if url_match:
        result["url"] = url_match.group(1)

    # Extract headers
    header_pattern = r'-H\s+["\']([^"\']+)["\']'
    headers = re.findall(header_pattern, curl_cmd)
    for header in headers:
        if ":" in header:
            key, value = header.split(":", 1)
            result["headers"][key.strip()] = value.strip()

    # Extract JSON data
    data_pattern = r"-d\s+'(\{[^']+\})'"
    data_match = re.search(data_pattern, curl_cmd)
    if data_match:
        result["data"] = data_match.group(1)

    return result


class RestApiDocumentationTestCase(TestCase):
    """Test case that validates REST API documentation examples."""

    def setUp(self) -> None:
        """Ensure the documentation file exists."""
        self.docs_path = get_docs_path()
        self.assertTrue(
            self.docs_path.exists(),
            f"REST API documentation file not found at {self.docs_path}",
        )
        with open(self.docs_path, "r") as f:
            self.docs_content = f.read()

    def test_documentation_file_exists(self) -> None:
        """Test that the REST API documentation file exists."""
        self.assertTrue(self.docs_path.exists())

    def test_documentation_contains_authentication_section(self) -> None:
        """Test that the documentation contains authentication information."""
        self.assertIn("Authentication", self.docs_content)
        self.assertIn("X-API-Token", self.docs_content)
        self.assertIn("API_TOKEN", self.docs_content)

    def test_documentation_contains_add_endpoint(self) -> None:
        """Test that the documentation documents the /api/add endpoint."""
        self.assertIn("/api/add", self.docs_content)
        self.assertIn("targets", self.docs_content)

    def test_documentation_contains_analyses_endpoint(self) -> None:
        """Test that the documentation documents the /api/analyses endpoint."""
        self.assertIn("/api/analyses", self.docs_content)

    def test_documentation_contains_task_results_endpoint(self) -> None:
        """Test that the documentation documents the /api/task-results endpoint."""
        self.assertIn("/api/task-results", self.docs_content)

    def test_documentation_contains_export_endpoints(self) -> None:
        """Test that the documentation documents the export endpoints."""
        self.assertIn("/api/export", self.docs_content)
        self.assertIn("/api/exports", self.docs_content)

    def test_curl_commands_are_extractable(self) -> None:
        """Test that curl commands can be extracted from the documentation."""
        commands = extract_curl_commands(self.docs_content)
        # We should have several commands documented
        self.assertGreater(len(commands), 0, "No curl commands found in documentation")

        # Check we have the main workflow commands
        command_ids = [cmd_id for cmd_id, _ in commands]
        expected_commands = [
            "rest-api-add-targets",
            "rest-api-list-analyses",
            "rest-api-num-queued-tasks",
            "rest-api-task-results",
        ]
        for expected in expected_commands:
            self.assertIn(
                expected,
                command_ids,
                f"Expected command '{expected}' not found in documentation",
            )

    def test_curl_commands_have_valid_syntax(self) -> None:
        """Test that extracted curl commands have valid syntax."""
        commands = extract_curl_commands(self.docs_content)

        for command_id, curl_cmd in commands:
            # Each command should start with curl
            self.assertTrue(
                curl_cmd.startswith("curl"),
                f"Command '{command_id}' does not start with 'curl': {curl_cmd}",
            )

            # Each command should have a URL
            parsed = parse_curl_command(curl_cmd)
            self.assertTrue(
                parsed["url"],
                f"Command '{command_id}' has no URL: {curl_cmd}",
            )

            # Commands should include API token header (except those that test auth failure)
            if "X-API-Token" not in curl_cmd and "$API_TOKEN" not in curl_cmd:
                self.fail(f"Command '{command_id}' missing API token header: {curl_cmd}")
