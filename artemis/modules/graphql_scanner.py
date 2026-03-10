import json
import re
from typing import Any, Dict, List, Optional

from karton.core import Task

from artemis import http_requests, load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url

# Comprehensive list of common GraphQL endpoint paths (superset of nuclei graphql-detect.yaml)
COMMON_GRAPHQL_PATHS = [
    "/graphql",
    "/graphiql",
    "/graphql.php",
    "/graphql-console",
    "/graphql-devtools",
    "/graphql-explorer",
    "/graphql-playground",
    "/graphql-playground-html",
    "/graphql/console",
    "/graphql/graphql-playground",
    "/graphql/v1",
    "/api/graphql",
    "/api/graphql/v1",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/v1/graphql",
    "/v1/graphiql",
    "/v1/graphql-explorer",
    "/v2/graphql",
    "/v2/graphiql",
    "/v3/graphql",
    "/playground",
    "/console",
    "/explorer",
    "/altair",
    "/query",
    "/gql",
    "/__graphql",
    "/graph",
    "/HyperGraphQL",
    "/___graphql",
    "/laravel-graphql-playground",
    "/sphinx-graphiql",
    "/subscriptions",
]

# The canonical introspection query — checks both __schema presence and gets queryType name
INTROSPECTION_QUERY = json.dumps(
    {
        "query": "{ __schema { queryType { name } types { name kind } } }",
    }
)

# A deliberately misspelled query to trigger "Did you mean..." field suggestions
FIELD_SUGGESTION_QUERY = json.dumps(
    {
        "query": "{ __typenme }",
    }
)

# HTML patterns that reliably identify GraphQL debug interfaces
DEBUG_INTERFACE_HTML_PATTERNS = [
    (r"graphiql", "GraphiQL"),
    (r"GraphQL\s*Playground", "GraphQL Playground"),
    (r"Apollo\s*(Studio|Sandbox|Explorer)", "Apollo Studio/Sandbox"),
    (r"graphql-playground", "GraphQL Playground"),
    (r"altair.*graphql", "Altair GraphQL Client"),
]

# Patterns indicating field suggestions are leaking schema information
FIELD_SUGGESTION_RESPONSE_PATTERNS = [
    r"[Dd]id you mean",
    r"[Ss]uggestion",
]


def _is_valid_introspection_response(data: Any) -> bool:
    """
    Verify that the response is a genuine GraphQL introspection response
    (not just any JSON containing '__schema' as a string somewhere).
    Requires a properly structured response with queryType and at least one type.
    """
    if not isinstance(data, dict):
        return False
    schema = data.get("data", {})
    if not isinstance(schema, dict):
        return False
    schema_obj = schema.get("__schema", {})
    if not isinstance(schema_obj, dict):
        return False
    # Must have queryType and a non-empty types list
    if schema_obj.get("queryType") is None:
        return False
    types = schema_obj.get("types", [])
    if not isinstance(types, list) or len(types) == 0:
        return False
    return True


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class GraphQLScanner(ArtemisBase):
    """
    Scans for exposed GraphQL endpoints and checks for security misconfigurations
    that go beyond what Nuclei's graphql-detect template covers:

    - Introspection enabled (MEDIUM): exposes full schema with types, queries, mutations.
      Nuclei's graphql-detect.yaml only flags this at 'info' severity (technology detection),
      not as a security misconfiguration. This module reports it at MEDIUM with schema details.
    - Exposed debug interfaces (MEDIUM): GraphiQL, Playground, Apollo Sandbox left in production
      — gives unauthenticated interactive query execution.
    - Field suggestion leaks (LOW): 'Did you mean...?' errors leak field names even when
      introspection is disabled.
    """

    identity = "graphql_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _detect_graphql_endpoint(self, base_url: str) -> Optional[str]:
        """
        Probe common paths to find a GraphQL endpoint.
        An endpoint is confirmed only if it returns a valid JSON response with
        a 'data' or 'errors' key — this minimizes false positives from non-GraphQL
        endpoints that happen to return 200 on these paths.
        """
        for path in COMMON_GRAPHQL_PATHS:
            url = base_url.rstrip("/") + path
            try:
                response = http_requests.post(
                    url,
                    json={"query": "{ __typename }"},
                    allow_redirects=True,
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, dict) and ("data" in data or "errors" in data):
                            self.log.info(f"GraphQL endpoint confirmed at {url}")
                            return url
                    except (json.JSONDecodeError, ValueError):
                        pass

            except Exception as e:
                self.log.debug(f"Error probing {url}: {e}")

        return None

    def _check_introspection(self, endpoint_url: str) -> Optional[Dict[str, Any]]:
        """
        Check if introspection is enabled.
        Uses strict response validation (_is_valid_introspection_response) to avoid
        false positives from endpoints that return JSON but aren't real GraphQL servers.
        """
        try:
            response = http_requests.post(
                endpoint_url,
                data=INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
                allow_redirects=True,
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                except (json.JSONDecodeError, ValueError):
                    return None

                if not _is_valid_introspection_response(data):
                    return None

                schema = data["data"]["__schema"]
                all_types = schema.get("types", [])
                # Filter out GraphQL built-in types
                custom_types = [
                    t["name"]
                    for t in all_types
                    if isinstance(t, dict)
                    and not t.get("name", "").startswith("__")
                    and t.get("name") not in ("String", "Int", "Float", "Boolean", "ID")
                    and t.get("kind") not in ("SCALAR",)
                ]
                return {
                    "endpoint": endpoint_url,
                    "query_type": schema.get("queryType", {}).get("name", "Unknown"),
                    "num_types_exposed": len(all_types),
                    "custom_types_sample": custom_types[:10],
                }
        except Exception as e:
            self.log.debug(f"Error checking introspection at {endpoint_url}: {e}")

        return None

    def _check_debug_interface(self, endpoint_url: str) -> Optional[Dict[str, Any]]:
        """
        Check if a GraphQL debug interface (GraphiQL, Playground, etc.) is exposed.
        Only matches HTML pages with specific identifying signatures — reduces FP
        compared to just matching on path names.
        """
        # Check the endpoint itself and common sibling debug paths
        base = endpoint_url.rsplit("/", 1)[0] if "/" in endpoint_url[8:] else endpoint_url
        urls_to_check = [endpoint_url] + [
            base + suffix for suffix in ["/graphiql", "/playground", "/altair"] if base + suffix != endpoint_url
        ]

        for url in urls_to_check:
            try:
                response = http_requests.get(url, allow_redirects=True)
                content_type = response.headers.get("content-type", "").lower()
                if response.status_code == 200 and "text/html" in content_type:
                    body = response.text
                    for pattern, label in DEBUG_INTERFACE_HTML_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            return {
                                "endpoint": url,
                                "interface_type": label,
                            }
            except Exception as e:
                self.log.debug(f"Error checking debug interface at {url}: {e}")

        return None

    def _check_field_suggestions(self, endpoint_url: str) -> Optional[Dict[str, Any]]:
        """
        Check if the endpoint leaks schema field names via suggestion error messages.
        Even when introspection is disabled, many GraphQL servers still suggest valid
        field names in error messages, enabling schema enumeration without introspection.
        """
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
                    return {
                        "endpoint": endpoint_url,
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

        # Phase 2: Run security checks
        findings: Dict[str, Any] = {"graphql_endpoint": endpoint}
        issues_found: List[str] = []

        introspection = self._check_introspection(endpoint)
        if introspection:
            findings["introspection"] = introspection
            issues_found.append(
                f"Introspection enabled at {endpoint} — "
                f"{introspection['num_types_exposed']} types exposed"
            )

        debug_interface = self._check_debug_interface(endpoint)
        if debug_interface:
            findings["debug_interface"] = debug_interface
            issues_found.append(
                f"Debug interface ({debug_interface['interface_type']}) exposed at {debug_interface['endpoint']}"
            )

        field_suggestions = self._check_field_suggestions(endpoint)
        if field_suggestions:
            findings["field_suggestions"] = field_suggestions
            issues_found.append(
                f"Field suggestions enabled at {endpoint} — schema can be enumerated without introspection"
            )

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
