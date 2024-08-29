import datetime
import random
import re
import urllib
from enum import Enum
from timeit import default_timer as timer
from typing import Any, Dict, List
from urllib.parse import parse_qs, unquote, urlencode, urlparse, urlunparse

import more_itertools
import requests
from karton.core import Task

from artemis import http_requests
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.http_requests import HTTPResponse
from artemis.karton_utils import check_connection_to_base_url_and_save_error
from artemis.module_base import ArtemisBase
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.sql_injection_data import HEADERS, SQL_ERROR_MESSAGES, URL_PARAMS
from artemis.task_utils import get_target_url


class Statements(Enum):
    sql_injection = "sql_injection"
    sql_time_based_injection = "sql_time_based_injection"
    headers_sql_injection = "headers_sql_injection"
    headers_time_based_sql_injection = "headers_time_based_sql_injection"


class SqlInjectionDetector(ArtemisBase):
    """
    Module for detecting SQL injection and time-based SQL injection vulnerabilities.
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
        concatenation = "&" if SqlInjectionDetector.is_url_with_parameters(new_url) else "?"
        new_url = f"{new_url}" + concatenation + "&".join([f"{key}={value}" for key, value in assignments.items()])
        return unquote(new_url)

    @staticmethod
    def is_response_time_within_threshold(elapsed_time: float) -> bool:
        if elapsed_time < Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD:
            return True
        return False

    def are_requests_time_efficient(self, url: str, **kwargs: Dict[str, Any]) -> bool:
        start = timer()
        try:
            if "headers" not in kwargs:
                http_requests.get(url)
            else:
                http_requests.get(url, headers=kwargs.get("headers"))
        except requests.exceptions.ReadTimeout:
            return False

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
        for key, value in HEADERS.items():
            headers.update({key: value + payload})
        return headers

    @staticmethod
    def create_status_reason(message: Any) -> str:
        status_reason = []
        for injection_message in message:
            status_reason.append(f"{injection_message.get('url')}: {injection_message.get('statement')}")
        return ", ".join(set(status_reason))

    @staticmethod
    def create_data(message: Any) -> Dict[str, List[str] | dict[str, str]]:
        message = list(more_itertools.unique_everseen(message))
        data = {
            "result": message,
            "statements": {
                "sql_injection": Statements.sql_injection.value,
                "sql_time_based_injection": Statements.sql_time_based_injection.value,
                "headers_sql_injection": Statements.headers_sql_injection.value,
                "headers_time_based_sql_injection": Statements.headers_time_based_sql_injection.value,
            },
        }
        return data

    def scan(self, urls: List[str], task: Task) -> List[Dict[str, Any]]:
        sql_injection_sleep_payloads = [
            f"'||sleep({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})||'",
            f"'||pg_sleep({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})||'",
        ]
        sql_injection_error_payloads = ["'", '"']
        message = []

        # The code below may look complicated and repetitive, but it shows how the scanning logic works.
        for current_url in urls:
            current_url_contains_error = self.contains_error(http_requests.get(current_url))

            for param_batch in more_itertools.batched(URL_PARAMS, 30):
                if self.is_url_with_parameters(current_url):
                    for error_payload in sql_injection_error_payloads:
                        url_with_payload = self.change_url_params(
                            url=current_url, payload=error_payload, param_batch=param_batch
                        )

                        if not current_url_contains_error and self.contains_error(http_requests.get(url_with_payload)):
                            message.append(
                                {
                                    "url": url_with_payload,
                                    "message": "It appears that this URL is vulnerable to SQL injection",
                                    "code": Statements.sql_injection.value,
                                }
                            )
                            if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                                return message

                    for sleep_payload in sql_injection_sleep_payloads:
                        url_with_sleep_payload = self.change_url_params(
                            url=current_url, payload=sleep_payload, param_batch=param_batch
                        )

                        # We explicitely want to re-check whether current URL is still time efficient
                        if self.are_requests_time_efficient(current_url) and not self.are_requests_time_efficient(
                            url_with_sleep_payload
                        ):
                            message.append(
                                {
                                    "url": url_with_sleep_payload,
                                    "statement": "It appears that this URL is vulnerable to time-based SQL injection",
                                    "code": Statements.sql_time_based_injection.value,
                                }
                            )
                            if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                                return message

                for error_payload in sql_injection_error_payloads:
                    url_with_payload = self.create_url_with_batch_payload(
                        url=current_url, param_batch=param_batch, payload=error_payload
                    )

                    if not current_url_contains_error and self.contains_error(http_requests.get(url_with_payload)):
                        message.append(
                            {
                                "url": url_with_payload,
                                "statement": "It appears that this URL is vulnerable to SQL injection",
                                "code": Statements.sql_injection.value,
                            }
                        )
                        if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                            return message

                for sleep_payload in sql_injection_sleep_payloads:
                    flags = []
                    url_with_sleep_payload = self.create_url_with_batch_payload(
                        url=current_url, param_batch=param_batch, payload=sleep_payload
                    )
                    for _ in range(
                        Config.Modules.SqlInjectionDetector.SQL_INJECTION_NUM_RETRIES_TO_CONFIRM_TIME_BASED_SQLI
                    ):
                        # We explicitely want to re-check whether current URL is still time efficient
                        if self.are_requests_time_efficient(current_url) and not self.are_requests_time_efficient(
                            url_with_sleep_payload
                        ):
                            flags.append(True)
                        else:
                            flags.append(False)
                            break

                    if all(flags):
                        message.append(
                            {
                                "url": url_with_sleep_payload,
                                "statement": "It appears that this URL is vulnerable to time-based SQL injection",
                                "code": Statements.sql_time_based_injection.value,
                            }
                        )
                        if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                            return message

            for error_payload in sql_injection_error_payloads:
                headers = self.create_headers(payload=error_payload)
                if not current_url_contains_error and self.contains_error(
                    http_requests.get(current_url, headers=headers)
                ):
                    message.append(
                        {
                            "url": current_url,
                            "statement": "It appears that this URL is vulnerable to SQL injection through HTTP Headers",
                            "code": Statements.headers_sql_injection.value,
                        }
                    )
                    if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                        return message

            for sleep_payload in sql_injection_sleep_payloads:
                flags = []
                headers = self.create_headers(sleep_payload)
                for _ in range(
                    Config.Modules.SqlInjectionDetector.SQL_INJECTION_NUM_RETRIES_TO_CONFIRM_TIME_BASED_SQLI
                ):
                    # We explicitely want to re-check whether current URL is still time efficient
                    if self.are_requests_time_efficient(current_url) and not self.are_requests_time_efficient(
                        current_url, headers=headers
                    ):
                        flags.append(True)
                    else:
                        flags.append(False)
                        break

                if all(flags):
                    message.append(
                        {
                            "url": current_url,
                            "statement": "It appears that this URL is vulnerable to time-based SQL injection through HTTP Headers",
                            "code": Statements.headers_time_based_sql_injection.value,
                        }
                    )
                    if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                        return message

        return message

    def run(self, current_task: Task) -> None:
        if check_connection_to_base_url_and_save_error(self.db, current_task):
            url = get_target_url(current_task)

            links = get_links_and_resources_on_same_domain(url)
            links.append(url)
            links = list(set(links) | set([self._strip_query_string(link) for link in links]))

            links = [
                link.split("#")[0]
                for link in links
                if not any(link.split("?")[0].lower().endswith(extension) for extension in STATIC_EXTENSIONS)
            ]

            random.shuffle(links)

            message = self.scan(urls=links[:50], task=current_task)

            if message:
                status = TaskStatus.INTERESTING
                status_reason = self.create_status_reason(message=message)
            else:
                status = TaskStatus.OK
                status_reason = None

            data = self.create_data(message=message)

            self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=data)


if __name__ == "__main__":
    SqlInjectionDetector().loop()
