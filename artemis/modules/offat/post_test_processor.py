from copy import deepcopy
from enum import Enum
from re import search as re_search, findall

from .regexs import sensitive_data_regex_patterns


class PostTestFiltersEnum(Enum):
    STATUS_CODE_FILTER = 0
    BODY_REGEX_FILTER = 1
    HEADER_REGEX_FILTER = 2


class PostRunTests:
    """class Includes tests that should be ran after running all the active test"""

    @staticmethod
    def run_broken_access_control_tests(
        results: list[dict], test_data_config: dict
    ) -> list[dict]:
        """
        Runs tests for broken access control

        Args:
            results (list[dict]): list of dict for tests results ran
            test_data_config (dict): user based config for running tests

        Returns:
            list[dict]: list of results

        Raises:
            Any Exception occurred during the test.
        """

        def re_match(patterns: list[str], endpoint: str) -> bool:
            """Matches endpoint for specified patterns

            Args:
                patterns (list[str]): endpoint regex pattern for matching endpoints
                endpoint (str): Endpoint to test for match

            Returns:
                bool: True if match found from any of the regex pattern else False

            Exception:
                Any Exception occurred during test procedure.
            """
            for pattern in patterns:
                if re_search(pattern, endpoint):
                    return True

            return False

        actor_based_tests = []
        actors = test_data_config.get('actors', [{}])
        actor_names = []
        for actor in actors:
            actor_name = list(actor.keys())[-1]
            unauth_endpoint_regex = actor[actor_name].get('unauthorized_endpoints', [])

            for result in results:
                if result.get('test_actor_name') != actor_name:
                    continue

                endpoint = result.get('endpoint', 'endpoint path not found')
                if not re_match(unauth_endpoint_regex, endpoint):
                    continue

                actor_names.append(actor_name)

                actor_test_result = deepcopy(result)
                actor_test_result['test_name'] = 'Broken Access Control'
                actor_test_result['vuln_details'] = {
                    True: f"BAC: Endpoint is accessible to {actor_name}",
                    False: 'Endpoint might not vulnerable to BAC',
                }
                actor_based_tests.append(actor_test_result)

        return PostRunTests.filter_status_code_based_results(actor_based_tests)

    @staticmethod
    def detect_data_exposure(results: list[dict]) -> list[dict]:
        """Detects data exposure against sensitive data regex
        patterns and returns dict of matched results

        Args:
            data (str): data to be analyzed for exposure

        Returns:
            dict: dictionary with tag as dict key and matched pattern as dict value
        """

        def detect_exposure(data: str) -> dict:
            # Dictionary to store detected data exposures
            detected_exposures = {}

            for pattern_name, pattern in sensitive_data_regex_patterns.items():
                matches = findall(pattern, data)
                if matches:
                    if isinstance(matches, list) and isinstance(matches[0], tuple):
                        matches = set.union(
                            *[set(match_tuple) for match_tuple in matches]
                        )
                        matches.discard('')
                        matches = list(matches)
                    detected_exposures[pattern_name] = matches
            return detected_exposures

        new_results = []

        for result in results:
            res_body = result.get('response_body')
            data_exposures_dict = detect_exposure(str(res_body))
            result['data_leak'] = data_exposures_dict
            new_results.append(result)

        return new_results

    @staticmethod
    # take a list and filter all at once
    def filter_status_code_based_results(results: list[dict]) -> list[dict]:
        new_results = []

        for result in results:
            new_result = deepcopy(result)
            response_status_code = result.get('response_status_code')
            success_codes = result.get('success_codes')

            # if response status code or success code is not
            # found then continue updating status of remaining
            # results
            if not response_status_code or not success_codes:
                continue

            new_result['vulnerable'] = (
                response_status_code in success_codes
            )  # True-> vulnerable, False-> not vulnerable
            new_results.append(new_result)

        return new_results

    @staticmethod
    def update_result_details(results: list[dict]):
        new_results = []
        for result in results:
            new_result = deepcopy(result)
            new_result['vuln_details'] = result['vuln_details'].get(
                result['vulnerable']
            )
            new_results.append(new_result)

        return new_results

    @staticmethod
    def matcher(results: list[dict]):
        """

        Args:
            results (list[dict]): list of dict for tests results ran
            match_location (ResponseMatchLocation): Search for match at
            specified location (`ResponseMatchLocation.BODY`,
            `ResponseMatchLocation.HEADER`,`ResponseMatchLocation.STATUS_CODE`).
            match_regex (str): regex to match as string

        Returns:
            list[dict]: list of results

        Raises:
            Any Exception occurred during the test.
        """
        new_results = []

        for result in results:
            match_location = result.get('response_filter')
            match_regex = result.get('response_match_regex')

            # skip test if match regex not found
            if not match_regex or not match_location:
                continue

            match match_location:
                case PostTestFiltersEnum.STATUS_CODE_FILTER.name:
                    target_data = result.get('response_status_code')
                case PostTestFiltersEnum.HEADER_REGEX_FILTER.name:
                    target_data = result.get('response_body')
                case _:  # PostTestFiltersEnum.BODY_REGEX_FILTER.name:
                    target_data = result.get('response_body')

            match_response = re_search(match_regex, target_data)
            new_result = deepcopy(result)
            new_result['regex_match_result'] = str(match_response)
            # True (Vulnerable) / False (Not Vulnerable)
            new_result['vulnerable'] = bool(match_response)
            new_results.append(new_result)

        return new_results
