import json
import os
import re
import subprocess
from typing import Any, Dict, Optional, Set, Tuple

from karton.core import Task
from openapi_spec_validator import validate
from openapi_spec_validator.readers import read_from_filename
from pydantic import BaseModel

from artemis import http_requests, load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.modules.data.api_scanner_data import COMMON_SPEC_PATHS, VULN_DETAILS_MAP
from artemis.sql_injection_data import SQL_ERROR_MESSAGES
from artemis.task_utils import get_target_url


class APIResult(BaseModel):
    url: str
    endpoint: str
    method: str
    vulnerable: bool
    vuln_details: Optional[str]
    curl_command: Optional[str] = None
    status_code: Optional[int]


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class APIScanner(ArtemisBase):
    """
    Scans API endpoints for vulnerabilities using OpenAPI/Swagger specifications.
    """

    identity = "api_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        if not os.path.exists("/offat"):
            subprocess.call(["git", "clone", "https://github.com/OWASP/OFFAT", "/offat"])
            patch_file_path = os.path.join(os.path.dirname(__file__), "data/offat/offat_artemis.patch")
            subprocess.call(["git", "-C", "/offat", "apply", patch_file_path])

        subprocess.call(["pip", "install", "-e", "/offat/src"])

    def discover_spec(self, base_url: str) -> Tuple[str, ...]:
        """Try to discover OpenAPI/Swagger specification from common paths."""
        for path in COMMON_SPEC_PATHS:
            try_url = base_url.rstrip("/") + "/" + path
            try:
                response = http_requests.get(try_url)
                if response.status_code == 200 and (
                    "openapi" in response.text.lower() or "swagger" in response.text.lower()
                ):
                    temp_file = f"/tmp/api_spec_{os.urandom(8).hex()}"
                    with open(temp_file, "w") as f:
                        f.write(response.content)

                    # Validate the spec
                    spec_dict, _ = read_from_filename(temp_file)
                    try:
                        validate(spec_dict)
                        return temp_file, try_url
                    except Exception as e:
                        self.log.info(f"Unable to validate spec at {try_url}: {e}")
                        os.unlink(temp_file)
                        continue
            except Exception as e:
                self.log.debug(f"Error checking {try_url}: {e}")
                continue
        return "", ""

    def scan(self, target_api_specification: str) -> Dict[str, Any]:
        output_file = "/tmp/output.json"

        offat_cmd = [
            "offat",
            "-f",
            target_api_specification,
            "-o",
            output_file,
            "--format",
            "json",
        ]

        if Config.Modules.APIScanner.ONLY_GET_REQUESTS:
            offat_cmd.extend(["--http-methods", "GET"])

        if Config.Miscellaneous.CUSTOM_USER_AGENT:
            offat_cmd.extend(["-H", f"User-Agent:{Config.Miscellaneous.CUSTOM_USER_AGENT}"])

        if self.requests_per_second_for_current_tasks:
            offat_cmd.extend(["-rl", str(self.requests_per_second_for_current_tasks)])

        subprocess.call(offat_cmd)

        with open(output_file) as f:
            file_contents = f.read()

        report: Dict[str, Any] = json.loads(file_contents)
        os.unlink(output_file)
        return report

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)

        # Try to discover the API spec
        spec_file, spec_file_url = self.discover_spec(url)
        if not spec_file:
            self.db.save_task_result(
                task=current_task, status=TaskStatus.OK, status_reason="No OpenAPI/Swagger specification found", data={}
            )
            return

        try:
            results = []
            test_results = self.scan(spec_file)

            vulns_found: Dict[str, Set[str]] = dict()
            for result in test_results.get("results", {}):
                vuln_details = result.get("vuln_details", "")
                response_headers = result.get("response_headers", {})
                if isinstance(response_headers, dict):
                    content_type = result.get("response_headers", {}).get("Content-Type", "").lower()
                else:
                    content_type = ""

                if not result.get("vulnerable", False):
                    continue
                # Removing BOLA and BOPLA results as they are prone to False Positives
                # Issue: https://github.com/CERT-Polska/Artemis/issues/1787
                if "BOLA" in vuln_details or "BOPLA" in vuln_details:
                    continue
                if "XSS/HTML Injection" in vuln_details and "text/html" not in content_type:
                    continue

                # Checking for SQL Error messages to decrease false positives
                if vuln_details in [
                    "Endpoint might be vulnerable to SQLi",
                    "One or more parameter is vulnerable to SQL Injection Attack",
                ] and not any(re.search(error, result.get("response_body", "")) for error in SQL_ERROR_MESSAGES):
                    continue

                vulns_found.setdefault(VULN_DETAILS_MAP.get(vuln_details, "Unknown Vulnerability"), set()).add(
                    result.get("endpoint", "")
                )
                results.append(
                    APIResult(
                        url=result.get("url"),
                        endpoint=result.get("endpoint"),
                        method=result.get("method"),
                        vulnerable=result.get("vulnerable"),
                        vuln_details=vuln_details,
                        curl_command=result.get("curl_command"),
                        status_code=result.get("response_status_code"),
                    )
                )

            # Remove duplicate results
            final_results = []
            seen = set()
            for result in results:
                identifier = (result.url, result.method, result.vuln_details, result.status_code)
                if identifier not in seen:
                    seen.add(identifier)
                    final_results.append(result)

            if final_results:
                status = TaskStatus.INTERESTING
                status_reason = "Found potential vulnerabilities in the API:"
                for vuln_type, endpoints in vulns_found.items():
                    status_reason += f"\n- {vuln_type}: {', '.join(endpoints)}"
            else:
                status = TaskStatus.OK
                status_reason = f"detected API on {spec_file_url}, no vulnerabilities found"

            self.db.save_task_result(
                task=current_task,
                status=status,
                status_reason=status_reason,
                data={"results": [result.model_dump() for result in final_results]},
            )

        except Exception as e:
            self.log.exception(f"Error scanning API: {e}")
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason=str(e),
                data={},
            )
        finally:
            try:
                if spec_file:
                    os.unlink(spec_file)
            except Exception as e:
                self.log.debug(f"Error cleaning up temp file: {e}")


if __name__ == "__main__":
    APIScanner().loop()
