"""Validate that the REST API documentation matches the real API source."""

import ast
import json
import os
import re
import unittest
from typing import Dict, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
DOCS_PATH = os.path.join(REPO_ROOT, "docs", "api", "rest-api.rst")
API_SOURCE_PATH = os.path.join(REPO_ROOT, "artemis", "api.py")
API_PREFIX = "/api"
SCALAR_TYPES = {"str", "int", "float", "bool", "bytes"}
ROUTE_DECORATORS = {"get", "post", "put", "delete", "patch"}


def extract_curl_commands_from_docs(filepath: str) -> Dict[str, str]:
    """Extract curl commands from the documentation, keyed by their comment identifier.

    Each curl command in the docs is preceded by a comment like:
        # rest-api-add-targets
    Returns a dict mapping those identifiers to the full curl command strings.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    commands: Dict[str, str] = {}
    pattern = r"# (rest-api-[\w-]+)\n\s+(curl\s+.*?)(?=\n\n|\n\.\.|$)"
    for match in re.finditer(pattern, content, re.DOTALL):
        identifier = match.group(1)
        curl_cmd = match.group(2).strip()
        # Join continuation lines (backslash at end of line)
        curl_cmd = re.sub(r"\\\n\s*", " ", curl_cmd)
        commands[identifier] = curl_cmd
    return commands


def parse_curl_command(curl_cmd: str) -> Tuple[str, str, Dict[str, str], str, Set[str]]:
    """Parse a curl command string and return (method, path, headers, body, query_params).

    Returns:
        method: HTTP method (GET, POST, etc.)
        path: URL path (e.g. /api/add)
        headers: dict of headers
        body: raw body string or empty string
        query_params: names of query parameters present in the URL
    """
    method = "GET"
    if "-X POST" in curl_cmd:
        method = "POST"
    elif "-X PUT" in curl_cmd:
        method = "PUT"
    elif "-X DELETE" in curl_cmd:
        method = "DELETE"

    url_match = re.search(r'https?://[^\s"\']+', curl_cmd)
    parsed_url = urlparse(url_match.group(0)) if url_match else None
    path = parsed_url.path if parsed_url else ""
    query_params = set(parse_qs(parsed_url.query).keys()) if parsed_url else set()

    # Extract headers
    headers: Dict[str, str] = {}
    for header_match in re.finditer(r'-H\s+"([^"]+)"', curl_cmd):
        key, _, value = header_match.group(1).partition(": ")
        headers[key] = value

    # Extract body
    body = ""
    data_match = re.search(r"-d\s+'(.*?)'", curl_cmd, re.DOTALL)
    if data_match:
        body = data_match.group(1)

    return method, path, headers, body, query_params


def extract_routes_from_api_source(filepath: str) -> Set[Tuple[str, str]]:
    """Extract all route definitions from artemis/api.py.

    Returns a set of (method, path) tuples where path includes the /api prefix.
    For example: {("POST", "/api/add"), ("GET", "/api/analyses"), ...}
    """
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    routes: Set[Tuple[str, str]] = set()
    # Match @router.get("/path", ...) and @router.post("/path", ...) patterns
    pattern = r'@router\.(get|post|put|delete|patch)\("(/[^"]*)"'
    for match in re.finditer(pattern, content):
        http_method = match.group(1).upper()
        route_path = API_PREFIX + match.group(2)
        routes.add((http_method, route_path))

    return routes


def _get_ast_name(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _unwrap_annotation(annotation: Optional[ast.AST]) -> Optional[ast.AST]:
    if not isinstance(annotation, ast.Subscript):
        return annotation

    container_name = _get_ast_name(annotation.value)
    if container_name == "Annotated":
        if isinstance(annotation.slice, ast.Tuple):
            return _unwrap_annotation(annotation.slice.elts[0])
        return _unwrap_annotation(annotation.slice)
    if container_name == "Optional":
        return _unwrap_annotation(annotation.slice)
    return annotation


def _annotation_is_complex(annotation: Optional[ast.AST]) -> bool:
    annotation = _unwrap_annotation(annotation)
    if annotation is None:
        return False

    if isinstance(annotation, ast.Subscript):
        return True

    annotation_name = _get_ast_name(annotation)
    if annotation_name is None:
        return True
    return annotation_name not in SCALAR_TYPES


def _is_fastapi_param(default: Optional[ast.AST], helper_name: str) -> bool:
    return isinstance(default, ast.Call) and _get_ast_name(default.func) == helper_name


def _fastapi_param_is_required(default: Optional[ast.AST]) -> bool:
    if not isinstance(default, ast.Call):
        return False
    if not default.args and not default.keywords:
        return True
    if any(isinstance(arg, ast.Constant) and arg.value is Ellipsis for arg in default.args):
        return True
    return any(
        keyword.arg == "default" and isinstance(keyword.value, ast.Constant) and keyword.value.value is Ellipsis
        for keyword in default.keywords
    )


def extract_route_parameter_locations(filepath: str) -> Dict[Tuple[str, str], Dict[str, Set[str]]]:
    """Extract documented route parameter locations from artemis/api.py."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    tree = ast.parse(content)
    route_definitions: Dict[Tuple[str, str], Dict[str, Set[str]]] = {}

    for node in tree.body:
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue

        defaults_offset = len(node.args.args) - len(node.args.defaults)
        defaults_by_arg: Dict[str, ast.AST | None] = {}
        for index, arg in enumerate(node.args.args):
            if index >= defaults_offset:
                defaults_by_arg[arg.arg] = node.args.defaults[index - defaults_offset]
            else:
                defaults_by_arg[arg.arg] = None

        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            if _get_ast_name(decorator.func.value) != "router" or decorator.func.attr not in ROUTE_DECORATORS:
                continue
            if not decorator.args or not isinstance(decorator.args[0], ast.Constant):
                continue

            route_path_value = decorator.args[0].value
            if not isinstance(route_path_value, str):
                continue

            route_path = API_PREFIX + route_path_value
            path_params = set(re.findall(r"{([^}]+)}", route_path))
            body_params: Set[str] = set()
            query_params: Set[str] = set()
            required_body_params: Set[str] = set()
            required_query_params: Set[str] = set()

            for arg in node.args.args:
                if arg.arg in {"self", "request"} or arg.arg in path_params:
                    continue

                default = defaults_by_arg[arg.arg]
                if _is_fastapi_param(default, "Body") or (default is None and _annotation_is_complex(arg.annotation)):
                    body_params.add(arg.arg)
                    if default is None or _fastapi_param_is_required(default):
                        required_body_params.add(arg.arg)
                else:
                    query_params.add(arg.arg)
                    if default is None or _fastapi_param_is_required(default):
                        required_query_params.add(arg.arg)

            route_definitions[(decorator.func.attr.upper(), route_path)] = {
                "body_params": body_params,
                "query_params": query_params,
                "required_body_params": required_body_params,
                "required_query_params": required_query_params,
            }

    return route_definitions


def normalize_path_for_matching(path: str) -> str:
    """Normalize a concrete URL path so it can match a route pattern.

    Replaces concrete path segments that look like IDs (integers, UUIDs, domain names
    in path params) with FastAPI-style {param} placeholders.

    E.g. /api/export/download-zip/1 -> /api/export/download-zip/{id}
         /api/is-blocklisted/example.com -> /api/is-blocklisted/{domain}
    """
    # /api/export/download-zip/<int> -> /api/export/download-zip/{id}
    path = re.sub(r"/export/download-zip/\d+", "/export/download-zip/{id}", path)
    # /api/export/delete/<int> -> /api/export/delete/{id}
    path = re.sub(r"/export/delete/\d+", "/export/delete/{id}", path)
    # /api/is-blocklisted/<domain> -> /api/is-blocklisted/{domain}
    path = re.sub(r"/is-blocklisted/[a-zA-Z0-9._-]+", "/is-blocklisted/{domain}", path)
    return path


class TestRestApiDocumentation(unittest.TestCase):
    """Verify that the REST API documentation references real, existing endpoints."""

    def setUp(self) -> None:
        self.assertTrue(
            os.path.exists(DOCS_PATH),
            f"REST API documentation not found at {DOCS_PATH}",
        )
        self.assertTrue(
            os.path.exists(API_SOURCE_PATH),
            f"API source code not found at {API_SOURCE_PATH}",
        )
        self.commands = extract_curl_commands_from_docs(DOCS_PATH)
        self.routes = extract_routes_from_api_source(API_SOURCE_PATH)
        self.route_parameter_locations = extract_route_parameter_locations(API_SOURCE_PATH)

    def test_curl_commands_are_extracted(self) -> None:
        """Verify that curl commands are successfully extracted from the documentation."""
        self.assertGreater(
            len(self.commands),
            0,
            "No curl commands found in the documentation. "
            "Ensure each code-block has a '# rest-api-*' comment identifier.",
        )

    def test_expected_curl_commands_present(self) -> None:
        """Verify all expected workflow commands are present in the documentation."""
        expected = [
            "rest-api-add-targets",
            "rest-api-list-analyses",
            "rest-api-num-queued-tasks",
            "rest-api-task-results",
            "rest-api-create-export",
            "rest-api-list-exports",
        ]
        for cmd_id in expected:
            self.assertIn(
                cmd_id,
                self.commands,
                f"Expected curl command '{cmd_id}' not found in docs. " f"Found: {sorted(self.commands.keys())}",
            )

    def test_all_documented_endpoints_exist_in_source(self) -> None:
        """Verify that every documented curl command targets a real API endpoint in api.py."""
        for cmd_id, curl_cmd in self.commands.items():
            method, path, _, _, _ = parse_curl_command(curl_cmd)
            normalized_path = normalize_path_for_matching(path)

            matching_routes = [(m, p) for m, p in self.routes if m == method and p == normalized_path]
            self.assertTrue(
                len(matching_routes) > 0,
                f"Documented command '{cmd_id}' references {method} {path} "
                f"(normalized: {normalized_path}) which does not exist in api.py. "
                f"Available routes: {sorted(self.routes)}",
            )

    def test_all_documented_commands_include_auth_header(self) -> None:
        """Verify that all documented curl commands include the X-API-Token header."""
        for cmd_id, curl_cmd in self.commands.items():
            _, _, headers, _, _ = parse_curl_command(curl_cmd)
            self.assertIn(
                "X-API-Token",
                headers,
                f"Documented command '{cmd_id}' is missing the X-API-Token header.",
            )

    def test_post_commands_include_content_type(self) -> None:
        """Verify that POST curl commands with JSON body include Content-Type header."""
        for cmd_id, curl_cmd in self.commands.items():
            method, _, headers, body, _ = parse_curl_command(curl_cmd)
            if method == "POST" and body:
                self.assertIn(
                    "Content-Type",
                    headers,
                    f"POST command '{cmd_id}' with body is missing Content-Type header.",
                )
                self.assertEqual(
                    headers["Content-Type"],
                    "application/json",
                    f"POST command '{cmd_id}' should use Content-Type: application/json.",
                )

    def test_post_commands_have_valid_json_body(self) -> None:
        """Verify that POST curl commands with -d flag contain valid JSON."""
        for cmd_id, curl_cmd in self.commands.items():
            method, _, _, body, _ = parse_curl_command(curl_cmd)
            if method == "POST" and body:
                try:
                    parsed = json.loads(body)
                    self.assertIsInstance(parsed, dict, f"Body of '{cmd_id}' should be a JSON object.")
                except json.JSONDecodeError as e:
                    self.fail(f"Command '{cmd_id}' has invalid JSON body: {e}\nBody: {body}")

    def test_documented_parameter_locations_match_api_source(self) -> None:
        """Verify that documented bodies and query strings match the handler signatures."""
        for cmd_id, curl_cmd in self.commands.items():
            method, path, _, body, query_params = parse_curl_command(curl_cmd)
            normalized_path = normalize_path_for_matching(path)
            route_key = (method, normalized_path)

            self.assertIn(
                route_key,
                self.route_parameter_locations,
                f"Could not find parameter metadata for documented endpoint {route_key}.",
            )

            route_definition = self.route_parameter_locations[route_key]
            documented_body_params = set(json.loads(body).keys()) if body else set()

            self.assertTrue(
                documented_body_params <= route_definition["body_params"],
                f"Command '{cmd_id}' documents non-body parameters in JSON: "
                f"{sorted(documented_body_params - route_definition['body_params'])}. "
                f"Allowed body parameters: {sorted(route_definition['body_params'])}.",
            )
            self.assertTrue(
                query_params <= route_definition["query_params"],
                f"Command '{cmd_id}' documents unexpected query parameters: "
                f"{sorted(query_params - route_definition['query_params'])}. "
                f"Allowed query parameters: {sorted(route_definition['query_params'])}.",
            )
            self.assertTrue(
                route_definition["required_body_params"] <= documented_body_params,
                f"Command '{cmd_id}' is missing required body parameters: "
                f"{sorted(route_definition['required_body_params'] - documented_body_params)}.",
            )
            self.assertTrue(
                route_definition["required_query_params"] <= query_params,
                f"Command '{cmd_id}' is missing required query parameters: "
                f"{sorted(route_definition['required_query_params'] - query_params)}.",
            )

    def test_add_endpoint_body_has_required_targets_field(self) -> None:
        """Verify the documented /api/add requests include the required 'targets' field."""
        for cmd_id in ["rest-api-add-targets", "rest-api-add-targets-with-options"]:
            if cmd_id not in self.commands:
                continue
            _, _, _, body, _ = parse_curl_command(self.commands[cmd_id])
            parsed = json.loads(body)
            self.assertIn(
                "targets",
                parsed,
                f"Command '{cmd_id}' must include 'targets' in the request body.",
            )
            self.assertIsInstance(
                parsed["targets"],
                list,
                f"Command '{cmd_id}': 'targets' must be a list.",
            )

    def test_export_endpoint_body_has_required_fields(self) -> None:
        """Verify the documented /api/export request includes the required fields."""
        self.assertIn(
            "rest-api-create-export",
            self.commands,
            "rest-api-create-export not found in docs",
        )
        _, _, _, body, _ = parse_curl_command(self.commands["rest-api-create-export"])
        parsed = json.loads(body)
        self.assertIn("language", parsed, "Export request must include 'language'.")
        self.assertIn(
            "skip_previously_exported",
            parsed,
            "Export request must include 'skip_previously_exported'.",
        )

    def test_documented_api_urls_use_correct_prefix(self) -> None:
        """Verify all documented URLs use the /api/ prefix."""
        for cmd_id, curl_cmd in self.commands.items():
            _, path, _, _, _ = parse_curl_command(curl_cmd)
            self.assertTrue(
                path.startswith("/api/"),
                f"Command '{cmd_id}' path '{path}' does not start with /api/. "
                f"All API endpoints must be under the /api prefix.",
            )

    def test_source_routes_are_extracted(self) -> None:
        """Verify that routes are successfully extracted from api.py."""
        self.assertGreater(
            len(self.routes),
            0,
            "No routes extracted from api.py.",
        )
        # Verify some known routes exist
        self.assertIn(("POST", "/api/add"), self.routes)
        self.assertIn(("GET", "/api/analyses"), self.routes)
        self.assertIn(("GET", "/api/num-queued-tasks"), self.routes)
        self.assertIn(("GET", "/api/task-results"), self.routes)
        self.assertIn(("GET", "/api/exports"), self.routes)
        self.assertIn(("POST", "/api/export"), self.routes)


if __name__ == "__main__":
    unittest.main()
