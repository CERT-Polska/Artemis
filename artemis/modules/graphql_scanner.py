import json
import re
from typing import Any, Dict, List, Optional

from karton.core import Task

from artemis import http_requests, load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url

COMMON_GRAPHQL_PATHS = [
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/playground",
    "/console",
    "/explorer",
    "/altair",
    "/query",
    "/gql",
    "/__graphql",
    "/graphql/console",
    "/graphql/playground",
]

# Introspection query to test if the schema is accessible
INTROSPECTION_QUERY = json.dumps(
    {
        "query": "{ __schema { queryType { name } types { name } } }",
    }
)

# Batch query to check if array-based batching is supported
BATCH_QUERY = json.dumps(
    [
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
    ]
)

# A deliberately misspelled query to trigger "Did you mean..." suggestions
FIELD_SUGGESTION_QUERY = json.dumps(
    {
        "query": "{ __typenme }",
    }
)

# Patterns indicating a debug interface is exposed
DEBUG_INTERFACE_PATTERNS = [
    r"graphiql",
    r"GraphQL\s*Playground",
    r"Apollo\s*(Studio|Sandbox|Explorer|Server)",
    r"graphql-playground",
    r"altair\s*graphql",
    r"voyager",  # GraphQL Voyager schema visualization
]

# Patterns indicating a valid introspection response
INTROSPECTION_RESPONSE_PATTERNS = [
    r'"__schema"',
    r'"queryType"',
    r'"types"',
]

# Patterns indicating field suggestions are leaking
FIELD_SUGGESTION_RESPONSE_PATTERNS = [
    r"[Dd]id you mean",
    r"[Cc]annot query field",
    r"[Ss]uggestion",
]


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class GraphQLScanner(ArtemisBase):
    """
    Scans for exposed GraphQL endpoints and common security misconfigurations:
    - Introspection enabled (schema leak)
    - Exposed debug interfaces (GraphiQL, Playground, Apollo Sandbox)
    - Batch query support (DoS amplification vector)
    - Field suggestion leaks (information disclosure via "Did you mean..." errors)
    """

    identity = "graphql_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _detect_graphql_endpoint(self, base_url: str) -> Optional[str]:
        """Probe common paths to find a GraphQL endpoint."""
        for path in COMMON_GRAPHQL_PATHS:
            url = base_url.rstrip("/") + path
            try:
                # Try a simple POST with a basic query
                response = http_requests.post(
                    url,
                    json={"query": "{ __typename }"},
                    allow_redirects=True,
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                        # A valid GraphQL response will have a "data" or "errors" key
                        if isinstance(data, dict) and ("data" in data or "errors" in data):
                            self.log.info(f"GraphQL endpoint found at {url} (POST)")
                            return url
                    except (json.JSONDecodeError, ValueError):
                        pass

                # Also check GET with a query parameter
                response = http_requests.get(
                    url,
                    params={"query": "{ __typename }"},
                    allow_redirects=True,
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, dict) and ("data" in data or "errors" in data):
                            self.log.info(f"GraphQL endpoint found at {url} (GET)")
                            return url
                    except (json.JSONDecodeError, ValueError):
                        pass

            except Exception as e:
                self.log.debug(f"Error probing {url}: {e}")
                continue

        return None

    def _check_introspection(self, endpoint_url: str) -> Optional[Dict[str, Any]]:
        """Check if introspection is enabled on the GraphQL endpoint."""
        try:
            response = http_requests.post(
                endpoint_url,
                data=INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
                allow_redirects=True,
            )

            if response.status_code == 200:
                body = response.text
                if all(re.search(pattern, body) for pattern in INTROSPECTION_RESPONSE_PATTERNS):
                    try:
                        data = response.json()
                        schema = data.get("data", {}).get("__schema", {})
                        type_names = [t.get("name", "") for t in schema.get("types", [])]
                        # Filter out built-in types for a cleaner report
                        custom_types = [t for t in type_names if not t.startswith("__") and t not in ("String", "Int", "Float", "Boolean", "ID")]
                        return {
                            "endpoint": endpoint_url,
                            "query_type": schema.get("queryType", {}).get("name", "Unknown"),
                            "num_types_exposed": len(type_names),
                            "custom_types_sample": custom_types[:10],  # Limit to 10 for readability
                        }
                    except (json.JSONDecodeError, ValueError, AttributeError):
                        return {
                            "endpoint": endpoint_url,
                            "query_type": "Unknown",
                            "num_types_exposed": 0,
                            "custom_types_sample": [],
                        }
        except Exception as e:
            self.log.debug(f"Error checking introspection at {endpoint_url}: {e}")

        return None

    def _check_debug_interface(self, endpoint_url: str) -> Optional[Dict[str, Any]]:
        """Check if a debug interface (GraphiQL, Playground, etc.) is exposed."""
        # Check both the endpoint URL and common debug paths
        urls_to_check = [endpoint_url]
        base = endpoint_url.rsplit("/", 1)[0] if "/" in endpoint_url else endpoint_url
        for suffix in ["/graphiql", "/playground", "/altair", "/voyager"]:
            candidate = base + suffix
            if candidate != endpoint_url:
                urls_to_check.append(candidate)

        for url in urls_to_check:
            try:
                response = http_requests.get(url, allow_redirects=True)
                if response.status_code == 200 and "text/html" in response.headers.get("content-type", "").lower():
                    body = response.text
                    for pattern in DEBUG_INTERFACE_PATTERNS:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            return {
                                "endpoint": url,
                                "interface_type": match.group(0).strip(),
                            }
            except Exception as e:
                self.log.debug(f"Error checking debug interface at {url}: {e}")

        return None

    def _check_batch_queries(self, endpoint_url: str) -> Optional[Dict[str, Any]]:
        """Check if the endpoint supports batch (array-based) queries."""
        try:
            response = http_requests.post(
                endpoint_url,
                data=BATCH_QUERY,
                headers={"Content-Type": "application/json"},
                allow_redirects=True,
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                    # A batch response is a JSON array of results
                    if isinstance(data, list) and len(data) >= 2:
                        # Verify they are actual GraphQL responses
                        if all(isinstance(item, dict) and ("data" in item or "errors" in item) for item in data):
                            return {
                                "endpoint": endpoint_url,
                                "batch_size_tested": 2,
                            }
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception as e:
            self.log.debug(f"Error checking batch queries at {endpoint_url}: {e}")

        return None

    def _check_field_suggestions(self, endpoint_url: str) -> Optional[Dict[str, Any]]:
        """Check if the endpoint leaks field names via suggestion messages."""
        try:
            response = http_requests.post(
                endpoint_url,
                data=FIELD_SUGGESTION_QUERY,
                headers={"Content-Type": "application/json"},
                allow_redirects=True,
            )

            if response.status_code in (200, 400):
                body = response.text
                if any(re.search(pattern, body) for pattern in FIELD_SUGGESTION_RESPONSE_PATTERNS):
                    # Extract suggested field names if possible
                    suggestions: List[str] = re.findall(r'"([^"]+)"', body)
                    return {
                        "endpoint": endpoint_url,
                        "suggestions_sample": suggestions[:5],
                    }
        except Exception as e:
            self.log.debug(f"Error checking field suggestions at {endpoint_url}: {e}")

        return None

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)

        # Phase 1: Detect GraphQL endpoint
        endpoint = self._detect_graphql_endpoint(url)

        if not endpoint:
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
                status_reason="No GraphQL endpoint detected",
                data={},
            )
            return

        # Phase 2: Run security checks on the discovered endpoint
        findings: Dict[str, Any] = {
            "graphql_endpoint": endpoint,
        }
        issues_found: List[str] = []

        introspection = self._check_introspection(endpoint)
        if introspection:
            findings["introspection"] = introspection
            issues_found.append(
                f"Introspection enabled — {introspection['num_types_exposed']} types exposed"
            )

        debug_interface = self._check_debug_interface(endpoint)
        if debug_interface:
            findings["debug_interface"] = debug_interface
            issues_found.append(
                f"Debug interface exposed: {debug_interface['interface_type']} at {debug_interface['endpoint']}"
            )

        batch_queries = self._check_batch_queries(endpoint)
        if batch_queries:
            findings["batch_queries"] = batch_queries
            issues_found.append("Batch queries supported (DoS amplification vector)")

        field_suggestions = self._check_field_suggestions(endpoint)
        if field_suggestions:
            findings["field_suggestions"] = field_suggestions
            issues_found.append("Field suggestions enabled (information disclosure)")

        # Phase 3: Save results
        if issues_found:
            status = TaskStatus.INTERESTING
            status_reason = f"GraphQL endpoint found at {endpoint} with security issues:\n" + "\n".join(
                f"- {issue}" for issue in issues_found
            )
        else:
            status = TaskStatus.OK
            status_reason = f"GraphQL endpoint found at {endpoint}, no security misconfigurations detected"

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data=findings,
        )


if __name__ == "__main__":
    GraphQLScanner().loop()
