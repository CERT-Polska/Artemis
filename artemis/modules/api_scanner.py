import os
import tempfile
from typing import List, Optional, Dict

from karton.core import Task
from pydantic import BaseModel

from artemis import http_requests, load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url
from openapi_spec_validator.readers import read_from_filename
from openapi_spec_validator import validate
from offat.generator import TestGenerator
from offat.tester_utils import is_host_up
from offat.post_test_processor import PostRunTests
from offat.utils import parse_server_url, result_to_curl
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


class Findings(Enum):
    SQLI_VULNERABILITY = "sql_injection_vulnerability"


class PayloadFor(Enum):
    BODY = 0
    QUERY = 1


class APIParser:
    def __init__(self, file_path: str):
        self.specification, _ = read_from_filename(file_path)
        self.base_url = self._get_server_uri()

        self.is_v3 = self._get_oas_version() == 3
        self.request_response_params = self._get_request_response_params()

        self._populate_hosts()

        if not (self.hosts and self.hosts[0]):
            raise ValueError('Host is invalid or not found')

        host_dict = self.hosts[0]
        self.http_scheme = host_dict['scheme']
        self.host = f'{host_dict["host"]}:{host_dict["port"]}'
        self.api_base_path = host_dict['basepath']
        self.base_url = f"{self.http_scheme}://{self.host}"

    def _populate_hosts(self):
        servers = self.specification.get('servers', [])
        hosts = []
        if not servers:
            self.log.error('Server URLs Not Found in spec file')

        for server in servers:
            scheme, host, port, basepath = parse_server_url(url=server.get('url'))
            hosts.append({
                'scheme': scheme,
                'host': host,
                'port': port,
                'basepath': basepath,
            })

        self.hosts = hosts

    def _get_oas_version(self):
        if self.specification.get("openapi"):
            return 3
        elif self.specification.get("swagger"):
            return 2
        self.log.error("only openapi and swagger specs are supported for now")

    def _get_request_response_params(self):
        requests = []
        paths = self.specification.get('paths', {})

        for path in paths.keys():
            path_params = paths[path].get('parameters', [])

            for http_method in paths.get(path, {}).keys():
                if http_method not in ['get', 'put', 'post', 'delete', 'options']:
                    continue

                request_parameters = paths[path][http_method].get('parameters', [])
                security = paths[path][http_method].get('security', [])

                body_params = []
                body_parameter_keys = (
                    paths[path][http_method].get('requestBody', {}).get('content', {})
                )

                for body_parameter_key in body_parameter_keys:
                    body_parameters_dict = paths[path][http_method]['requestBody'][
                        'content'
                    ][body_parameter_key]

                    required = paths[path][http_method]['requestBody'].get('required')
                    description = paths[path][http_method]['requestBody'].get(
                        'description'
                    )
                    body_param = self._get_param_definition_schema(body_parameters_dict)

                    body_params.append(
                        {
                            'in': 'body',
                            'name': body_parameter_key,
                            'description': description,
                            'required': required,
                            'schema': body_param,
                        }
                    )

                response_params = []
                response_params = self._get_response_definition_schema(
                    paths[path][http_method].get('responses', {})
                )

                request_parameters += body_params
                requests.append(
                    {
                        'http_method': http_method,
                        'path': path,
                        'request_params': request_parameters,
                        'response_params': response_params,
                        'path_params': path_params,
                        'body_params': body_params,
                        'security': security,
                    }
                )

        return requests

    def _fetch_schema_from_spec(self, param_schema_ref: str) -> dict:
        schema_spec_path = param_schema_ref.split('/')[1:]

        if len(schema_spec_path) > 3:
            return {}

        schema_data: dict = self.specification
        for child_ele in schema_spec_path:
            schema_data: dict = schema_data.get(child_ele, {})

        return schema_data

    def _get_param_definition_schema(self, param: Dict):
        param_schema = param.get('schema')
        if param_schema:
            param_schema_ref = param_schema.get('$ref')
            if param_schema_ref:
                param_schema = self._fetch_schema_from_spec(param_schema_ref)
        return param_schema

    def _get_response_definition_schema(self, responses: Dict):
        for status_code in responses.keys():
            content = responses[status_code].get('content', None)
            if content:
                status_code_content_type_responses = content.keys()
                for status_code_content_type in status_code_content_type_responses:
                    status_code_content = responses[status_code]['content'][
                        status_code_content_type
                    ].keys()
                    if 'parameters' in status_code_content:
                        responses[status_code]['schema'] = responses[status_code][
                            'content'
                        ][status_code_content_type]['parameters']
                    elif 'schema' in status_code_content:
                        responses[status_code][
                            'schema'
                        ] = self._get_param_definition_schema(
                            responses[status_code]['content'][status_code_content_type]
                        )
            else:
                ref = responses[status_code].get('$ref', None)
                if ref:
                    responses[status_code]['schema'] = self._fetch_schema_from_spec(ref)
        return responses

    def _get_server_uri(self):
        return self.specification.get("servers")[0].get("url")


class TestRunner:
    def __init__(self):
        self._client = http_requests

    def _generate_payloads(
        self, params: List[Dict], payload_for: PayloadFor = PayloadFor.BODY
    ):
        if payload_for not in [PayloadFor.BODY, PayloadFor.QUERY]:
            raise ValueError(
                '`payload_for` arg only supports `PayloadFor.BODY, PayloadFor.QUERY` value'
            )

        body_payload = {}
        query_payload = {}

        for param in params:
            param_in = param.get('in')
            param_name = param.get('name')
            param_value = param.get('value')

            # TODO:handle schema

            match param_in:
                case 'body':
                    body_payload[param_name] = param_value
                case 'query':
                    query_payload[param_name] = param_value
                case _:
                    continue

        match payload_for:
            case PayloadFor.BODY:
                return body_payload
            case PayloadFor.QUERY:
                return query_payload
        return {}

    def send_request(self, test_task: Dict):
        url = test_task.get('url')
        http_method = test_task.get('method')
        args = test_task.get('args')
        kwargs = test_task.get('kwargs', {})
        body_params = test_task.get('body_params')
        query_params = test_task.get('query_params')

        if body_params and str(http_method).upper() not in ['GET', 'OPTIONS']:
            kwargs['json'] = self._generate_payloads(
                body_params, payload_for=PayloadFor.BODY
            )

        if query_params:
            kwargs['params'] = self._generate_payloads(
                query_params, payload_for=PayloadFor.QUERY
            )

        test_result = test_task
        try:
            response = http_requests.request(
                url=url, method=http_method, *args, **kwargs
            )
            test_result['request_headers'] = response.request.headers
            test_result['response_headers'] = response.headers
            test_result['response_body'] = response.text
            test_result['response_status_code'] = response.status_code
            test_result['error'] = False

        except Exception as e:
            test_result['request_headers'] = []
            test_result['response_headers'] = []
            test_result['response_body'] = 'No Response Body Found'
            test_result['response_status_code'] = -1
            test_result['error'] = e

        test_result['curl_command'] = result_to_curl(test_result)
        return test_result

    def run_tests(self, test_tasks: List):
        test_results = []
        for test_task in test_tasks:
            test_results.append(self.send_request(test_task))

        test_results = PostRunTests.filter_status_code_based_results(test_results)
        test_results = PostRunTests.update_result_details(test_results)
        test_results = PostRunTests.detect_data_exposure(test_results)
        return test_results


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
            api_parser = APIParser(spec_file)

            if not is_host_up(openapi_parser=api_parser):
                self.db.save_task_result(
                    task=current_task,
                    status=TaskStatus.OK,
                    status_reason="Host is not responding",
                    data={}
                )
                return

            test_generator = TestGenerator()
            test_runner = TestRunner()
            results = []

            tests_list = []
            tests_list.append(test_generator.sqli_fuzz_params_test(api_parser))
            tests_list.append(test_generator.sqli_in_uri_path_fuzz_test(api_parser))

            test_results = []
            for tests in tests_list:
                test_results.append(test_runner.run_tests(tests))

            for result in test_results:
                if result.get("vulnerable", False) or result.get("vuln_details"):
                    results.append(APIResult(
                        url=result.get("url"),
                        method=result.get("method"),
                        vulnerable=True,
                        details=result.get("vuln_details"),
                        curl_command=result.get("curl_command"),
                        status_code=result.get("response_status_code")
                    ))

            if results:
                status = TaskStatus.INTERESTING
                status_reason = "Found potential SQL injection vulnerabilities"
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
