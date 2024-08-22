import datetime
import re
import urllib
from timeit import default_timer as timer
from typing import Any, Dict, List
from urllib.parse import parse_qs, unquote, urlencode, urlparse, urlunparse

import more_itertools
from karton.core import Task

from artemis import http_requests
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.http_requests import HTTPResponse
from artemis.karton_utils import check_connection_to_base_url_and_save_error
from artemis.module_base import ArtemisBase
from artemis.sql_injection_data import HEADER_KEYS, SQL_ERROR_MESSAGES, URL_PARAMS
from artemis.task_utils import get_target_url


class SqlInjectionDetector(ArtemisBase):
    """
    Module for detecting SQL Injection and Base Time SQL Injection vulnerabilities.
    """

    identity = "sql_injection_detector"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    @staticmethod
    def _strip_query_string(url: str) -> str:
        url_parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(url_parsed._replace(query="", fragment=""))

    def create_url_with_batch_payload(self, url: str, param_batch: tuple[Any], payload: str) -> str:
        assignments = {key: payload for key in param_batch}
        concatenation = "&" if self.is_url_with_parameters(url) else "?"

        url_with_payload = f"{url}{concatenation}" + "&".join([f"{key}={value}" for key, value in assignments.items()])

        return url_with_payload

    @staticmethod
    def is_url_with_parameters(url: str) -> bool:
        if re.search("/?/*=", url):
            return True
        return False

    @staticmethod
    def change_url_params(url: str, payload: str, param_batch: tuple[Any]) -> str:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        params = list(query_params.keys())
        new_query_params = {}
        assignments = {key: payload for key in param_batch}

        for param in params:
            new_query_params[param] = [payload]

        new_query_string = urlencode(new_query_params, doseq=True)
        new_url = urlunparse(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query_string,
                parsed_url.fragment,
            )
        )
        new_url = f"{new_url}" + "&".join([f"{key}={value}" for key, value in assignments.items()])
        return unquote(new_url)

    @staticmethod
    def is_response_time_within_threshold(elapsed_time: float) -> bool:
        if elapsed_time < Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD:
            return True
        return False

    def are_requests_time_efficient(self, url: str, **kwargs: Dict[str, Any]) -> bool:
        start = timer()
        if "headers" not in kwargs:
            http_requests.get(url)
        else:
            http_requests.get(url, headers=kwargs.get("headers"))
        elapsed_time = datetime.timedelta(seconds=timer() - start).seconds

        flag = self.is_response_time_within_threshold(elapsed_time)

        return flag

    @staticmethod
    def contains_error(response: HTTPResponse) -> bool | None:
        if response.status_code == 500:
            return True

        for message in SQL_ERROR_MESSAGES:
            if re.search(message, response.content):
                return True
        return False

    @staticmethod
    def create_headers(payload: str) -> dict[str, str]:
        headers = {}
        for key in HEADER_KEYS:
            headers.update({key: payload})
        return headers

    @staticmethod
    def create_status_reason_output(message: Any) -> str:
        status_reason_output = []
        for output in message:
            status_reason_output.append(f"{output.get('url')}: {output.get('statement')}")
        return str(list(set(status_reason_output)))

    def scan(self, urls: List[str], task: Task) -> Dict[str, object]:
        task_result = {
            "task_host": get_target_url(task),
            "status": task.status,
            "message": [],
        }
        sql_injection_sleep_payloads = [
            f"'||sleep({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})||'",
            f"'||pg_sleep({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})||'",
        ]
        sql_injection_error_payloads = ["'", '"']
        message = []

        # The code below may look complicated and repetitive, but it shows how the scanning logic works.
        for current_url in urls:
            for param_batch in more_itertools.batched(URL_PARAMS, 10):
                if self.is_url_with_parameters(current_url):
                    for error_payload in sql_injection_error_payloads:
                        url_with_payload = self.change_url_params(
                            url=current_url, payload=error_payload, param_batch=param_batch
                        )

                        if not self.contains_error(http_requests.get(current_url)) and self.contains_error(
                            http_requests.get(url_with_payload)
                        ):
                            message.append(
                                {
                                    "url": url_with_payload,
                                    "message": "It appears that this url is vulnerable to SQL Injection",
                                    "code": 1,
                                }
                            )

                    for sleep_payload in sql_injection_sleep_payloads:
                        url_with_sleep_payload = self.change_url_params(
                            url=current_url, payload=sleep_payload, param_batch=param_batch
                        )

                        if self.are_requests_time_efficient(current_url) and not self.are_requests_time_efficient(
                            url_with_sleep_payload
                        ):
                            message.append(
                                {
                                    "url": url_with_sleep_payload,
                                    "statement": "It appears that this url is vulnerable to SQL Time Base Injection",
                                    "code": 2,
                                }
                            )

                for error_payload in sql_injection_error_payloads:
                    url_with_payload = self.create_url_with_batch_payload(
                        url=current_url, param_batch=param_batch, payload=error_payload
                    )

                    if not self.contains_error(http_requests.get(current_url)) and self.contains_error(
                        http_requests.get(url_with_payload)
                    ):
                        message.append(
                            {
                                "url": url_with_payload,
                                "statement": "It appears that this url is vulnerable to SQL Injection",
                                "code": 1,
                            }
                        )

                for sleep_payload in sql_injection_sleep_payloads:
                    flags = []
                    url_with_sleep_payload = self.create_url_with_batch_payload(
                        url=current_url, param_batch=param_batch, payload=sleep_payload
                    )
                    for _ in range(3):
                        if self.are_requests_time_efficient(current_url) and not self.are_requests_time_efficient(
                            url_with_sleep_payload
                        ):
                            flags.append(True)
                        else:
                            flags.append(False)

                    if all(flags):
                        message.append(
                            {
                                "url": url_with_sleep_payload,
                                "statement": "It appears that this url is vulnerable to SQL Time Base Injection",
                                "code": 2,
                            }
                        )

            for error_payload in sql_injection_error_payloads:
                headers = self.create_headers(payload=error_payload)
                if not self.contains_error(http_requests.get(current_url)) and self.contains_error(
                    http_requests.get(current_url, headers=headers)
                ):
                    message.append(
                        {
                            "url": current_url,
                            "statement": "It appears that this url is vulnerable to SQL Injection through HTTP Headers",
                            "code": 3,
                        }
                    )

            for sleep_payload in sql_injection_sleep_payloads:
                headers = self.create_headers(sleep_payload)
                if self.are_requests_time_efficient(current_url) and not self.are_requests_time_efficient(
                    current_url, headers=headers
                ):
                    message.append(
                        {
                            "url": current_url,
                            "statement": "It appears that this url is vulnerable to SQL Time Base Injection through HTTP Headers",
                            "code": 4,
                        }
                    )

        task_result["message"] = message
        return task_result

    def run(self, current_task: Task) -> None:
        if check_connection_to_base_url_and_save_error(self.db, current_task):
            url = get_target_url(current_task)

            links = get_links_and_resources_on_same_domain(url)
            links.append(url)
            links = list(set(links) | set([self._strip_query_string(link) for link in links]))

            result = self.scan(urls=links, task=current_task)
            message = result["message"]
            if message:
                status = TaskStatus.INTERESTING
                status_reason = self.create_status_reason_output(message)
            else:
                status = TaskStatus.OK
                status_reason = None

            data = {
                "result": message,
                "statements": {
                    "sql_injection": 1,
                    "sql_time_base_injection": 2,
                    "headers_sql_injection": 3,
                    "headers_time_base_sql_injection": 4,
                },
            }

            self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=data)


if __name__ == "__main__":
    SqlInjectionDetector().loop()
