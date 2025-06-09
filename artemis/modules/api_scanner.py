import os
import json
import tempfile
from typing import List, Optional, Dict

from karton.core import Task
from pydantic import BaseModel

from artemis import http_requests, load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url
from openapi_spec_validator.readers import read_from_filename
from openapi_schema_validator import validate
from enum import Enum


COMMON_SPEC_PATHS = [
    "/swagger.json",
    "/v2/swagger.json",
    "/v3/api-docs",
    "/openapi.json",
    "/api-docs",
    "/api/docs"
    "/docs/swagger.json"
]


class APIResult(BaseModel):
    url: str
    method: str
    vulnerable: bool
    details: Optional[str]
    curl_command: Optional[str]
    status_code: Optional[int]


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class APIScanner(ArtemisBase):
    """
    Scans API endpoints for vulnerabilities based on OpenAPI/Swagger specifications.
    """

    identity = "api_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def discover_spec(self, base_url: str) -> Optional[str]:
        """Try to discover OpenAPI/Swagger specification from common paths."""
        for path in COMMON_SPEC_PATHS:
            try_url = base_url.rstrip('/') + path
            try:
                response = http_requests.get(try_url)
                if response.status_code == 200 and ("openapi" in response.text.lower() or "swagger" in response.text.lower()):
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
                        f.write(response.content)
                        temp_file = f.name

                    # Validate the spec
                    spec_dict, _ = read_from_filename(temp_file)
                    try:
                        validate(spec_dict)
                        return temp_file
                    except Exception as e:
                        self.log.info(f"Unable to validate spec at {try_url}: {e}")
                        continue
            except Exception as e:
                self.log.debug(f"Error checking {try_url}: {e}")
                continue
        return None
    
    def install_offat(self):
        if not os.path.exists("/offat"):
            os.system("git clone https://github.com/OWASP/OFFAT /offat")
            os.system(f"git -C /offat apply {os.path.join(os.path.dirname(__file__), "data/offat", "offat_artemis.patch")}")

        os.system("pip install -e /offat/src")
    
    def scan(self, target_api_specification: str):
        output_file = "/tmp/output.json"
        os.system(' '.join(["offat", "-f", target_api_specification, "--only-get-requests", "-o", output_file, "--format", "json"]))

        with open(output_file) as f:
            file_contents = f.read()
    
        report = json.loads(file_contents)
        os.unlink(output_file)
        return report

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)

        # Try to discover the API spec
        spec_file = self.discover_spec(url)
        if not spec_file:
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.OK,
                status_reason="No OpenAPI/Swagger specification found",
                data={}
            )
            return
        
        try:
            results = []
            test_results = self.scan(spec_file)

            for result in test_results:
                if result.get("vulnerable", False):
                    results.append(APIResult(
                        url=result.get("url"),
                        method=result.get("method"),
                        vulnerable=result.get("vulnerable"),
                        details=result.get("vuln_details"),
                        curl_command=result.get("curl_command"),
                        status_code=result.get("response_status_code")
                    ))

            if results:
                status = TaskStatus.INTERESTING
                status_reason = "Found potential vulnerabilities in the api"
            else:
                status = TaskStatus.OK
                status_reason = None

            self.db.save_task_result(
                task=current_task,
                status=status,
                status_reason=status_reason,
                data={"results": [result.dict() for result in results]},
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
