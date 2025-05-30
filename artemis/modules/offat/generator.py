'''
This module contains the TestGenerator class which is used to generate API test checks.
'''
from copy import deepcopy
from .fuzzer import fill_params
from .post_test_processor import PostTestFiltersEnum
# from .fuzzer import generate_random_int
# from ..config_data_handler import populate_user_data
# from ..exploit import APIModule
# from .parsers import SwaggerParser, OpenAPIv3Parser
from .utils import join_uri_path, get_unique_params


class TestGenerator:
    """
    Class to generate API test checks.

    This class provides methods to generate API test checks for various scenarios.

    Attributes:
        None

    Methods:
        check_unsupported_http_methods: Checks whether endpoint supports
        undocumented/unsupported HTTP methods.
        sqli_fuzz_params: Performs SQL injection (SQLi) parameter fuzzing
        based on the provided OpenAPIParser instance.
    """

    def __init__(self, headers: dict = None) -> None:  # type: ignore
        """
        Initializes an instance of the TestGenerator class.

        Args:
            headers (dict, optional): A dictionary of headers to be set
            for the instance. Defaults to None.

        Returns:
            None

        Example:
            headers = {"Content-Type": "application/json", "Authorization": "Bearer xyz123"}
            tester = TestGenerator(headers)
        """
        self._headers = headers

    def __fuzz_request_params(
        self, openapi_parser
    ) -> list[dict]:
        base_url: str = openapi_parser.base_url
        request_response_params: list[dict] = openapi_parser.request_response_params

        tasks = []
        for path_obj in request_response_params:
            # handle path params from request_params
            request_params = path_obj.get('request_params', [])
            request_params = fill_params(request_params, openapi_parser.is_v3)
            security = path_obj.get('security', [])

            # get params based on their position in request
            request_body_params = list(
                filter(lambda x: x.get('in') == 'body', request_params)
            )
            request_query_params = list(
                filter(lambda x: x.get('in') == 'query', request_params)
            )
            path_params_in_body = list(
                filter(lambda x: x.get('in') == 'path', request_params)
            )

            # get endpoint path
            endpoint_path: str = path_obj.get('path')  # type: ignore

            # get path params and fill them
            path_params = path_obj.get('path_params', [])
            path_params = fill_params(path_params, openapi_parser.is_v3)

            # get unique path params
            path_params = get_unique_params(path_params, path_params_in_body)

            for path_param in path_params:
                path_param_name = path_param.get('name')
                path_param_value = path_param.get('value')

                endpoint_path = endpoint_path.replace(
                    '{' + str(path_param_name) + '}', str(path_param_value)
                )

            tasks.append(
                {
                    'url': join_uri_path(
                        base_url, openapi_parser.api_base_path, endpoint_path
                    ),
                    'endpoint': join_uri_path(
                        openapi_parser.api_base_path, endpoint_path
                    ),
                    'method': path_obj.get('http_method', '').upper(),
                    'body_params': request_body_params,
                    'query_params': request_query_params,
                    'path_params': path_params,
                    'security': security,
                }
            )

        return tasks

    def __inject_payload_in_params(self, request_params: list[dict], payload: str):
        request_params = deepcopy(request_params)

        # inject sqli payload as param value
        for request_param_data in request_params:
            # TODO: inject sqli payloads in other data types as well
            if request_param_data.get('type') == 'string':
                request_param_data['value'] = payload

        return request_params

    def sqli_fuzz_params_test(
        self,
        openapi_parser,
        *args,
        success_codes: list[int] | None = None,
        **kwargs,
    ):
        if success_codes is None:
            success_codes = [500]

        # APPROACH: first send sqli in all params, if error is generated
        # then enumerate one by one or ask user to pentest manually using
        # sqlmap
        tasks = []
        basic_sqli_payloads = [
            "' OR 1=1 ;--",
            "' UNION SELECT 1,2,3 -- -",
            "' OR '1'='1--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))abc)",
            "' AND SLEEP(5) --",
        ]

        fuzzed_request_list = self.__fuzz_request_params(openapi_parser)

        # inject SQLi payloads in string variables
        for sqli_payload in basic_sqli_payloads:
            for request_obj in fuzzed_request_list:
                # handle body request params
                body_request_params = request_obj.get('body_params', [])
                malicious_body_request_params = self.__inject_payload_in_params(
                    body_request_params, sqli_payload
                )

                # handle query request params
                query_request_params = request_obj.get('query_params', [])
                malicious_query_request_params = self.__inject_payload_in_params(
                    query_request_params, sqli_payload
                )

                # BUG: for few SQLi test, path params injected value is not matching
                # with final URI path params in output
                request_obj['test_name'] = 'SQLi Test'

                request_obj['body_params'] = malicious_body_request_params
                request_obj['query_params'] = malicious_query_request_params
                request_obj['args'] = args
                request_obj['kwargs'] = kwargs

                request_obj['malicious_payload'] = sqli_payload

                request_obj['vuln_details'] = {
                    True: 'One or more parameter is vulnerable to SQL Injection Attack',
                    False: 'Parameters are not vulnerable to SQLi Payload',
                }
                request_obj['success_codes'] = success_codes
                request_obj[
                    'response_filter'
                ] = PostTestFiltersEnum.STATUS_CODE_FILTER.name
                tasks.append(deepcopy(request_obj))

        return tasks

    def sqli_in_uri_path_fuzz_test(
        self,
        openapi_parser,
        *args,
        success_codes: list[int] | None = None,
        **kwargs,
    ):
        '''Generate Tests for SQLi in endpoint path

        Args:
            openapi_parser (OpenAPIParser): An instance of the OpenAPIParser class
            containing the parsed OpenAPI specification.
            success_codes (list[int], optional): A list of HTTP success codes to
            consider as successful BOLA responses. Defaults to [200, 201, 301].
            *args: Variable-length positional arguments.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            list[dict]: list of dict containing test case for endpoint

        Raises:
            Any exceptions raised during the execution.
        '''
        if success_codes is None:
            success_codes = [500]

        base_url: str = openapi_parser.base_url
        request_response_params: list[dict] = openapi_parser.request_response_params

        # filter path containing params in path
        endpoints_with_param_in_path = list(
            filter(
                lambda path_obj: '/{' in path_obj.get('path'),  # type: ignore
                request_response_params,  # type: ignore
            )  # type: ignore
        )

        basic_sqli_payloads = [
            "' OR 1=1 ;--",
            "' UNION SELECT 1,2,3 -- -",
            "' OR '1'='1--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))abc)",
            "' AND SLEEP(5) --",
        ]

        tasks = []
        for sqli_payload in basic_sqli_payloads:
            for path_obj in endpoints_with_param_in_path:
                # handle path params from request_params
                request_params = path_obj.get('request_params', [])
                request_params = fill_params(request_params, openapi_parser.is_v3)

                # get request body params
                request_body_params = list(
                    filter(lambda x: x.get('in') == 'body', request_params)
                )

                # handle path params from path_params
                # and replace path params by value in
                # endpoint path
                endpoint_path: str = path_obj.get('path')

                path_params = path_obj.get('path_params', [])
                path_params_in_body = list(
                    filter(lambda x: x.get('in') == 'path', request_params)
                )
                path_params += path_params_in_body
                path_params = fill_params(path_params, openapi_parser.is_v3)

                for path_param in path_params:
                    path_param_name = path_param.get('name')
                    endpoint_path = endpoint_path.replace(
                        '{' + str(path_param_name) + '}', str(sqli_payload)
                    )

                request_query_params = list(
                    filter(lambda x: x.get('in') == 'query', request_params)
                )

                tasks.append(
                    {
                        'test_name': 'SQLi Test in URI Path with Fuzzed Params',
                        'url': join_uri_path(
                            base_url, openapi_parser.api_base_path, endpoint_path
                        ),
                        'endpoint': join_uri_path(
                            openapi_parser.api_base_path, endpoint_path
                        ),
                        'method': path_obj.get('http_method').upper(),
                        'body_params': request_body_params,
                        'query_params': request_query_params,
                        'path_params': path_params,
                        'malicious_payload': sqli_payload,
                        'args': args,
                        'kwargs': kwargs,
                        'vuln_details': {
                            True: 'Endpoint might be vulnerable to SQli',
                            False: 'Endpoint is not vulnerable to SQLi',
                        },
                        'success_codes': success_codes,
                        'response_filter': PostTestFiltersEnum.STATUS_CODE_FILTER.name,
                    }
                )

        return tasks
