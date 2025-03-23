import datetime
import random
import re
import urllib
from enum import Enum
from timeit import default_timer as timer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlencode, urlparse, urlunparse

import more_itertools
import requests
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.http_requests import HTTPResponse
from artemis.module_base import ArtemisBase
from artemis.modules.data.parameters import URL_PARAMS
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.sql_injection_data import HEADERS, SQL_ERROR_MESSAGES
from artemis.task_utils import get_target_url


class Statements(Enum):
    sql_injection = "sql_injection"
    sql_time_based_injection = "sql_time_based_injection"
    headers_sql_injection = "headers_sql_injection"
    headers_time_based_sql_injection = "headers_time_based_sql_injection"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
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
    def change_sleep_to_0(payload: str) -> str:
        # This is to replace sleep(5) with sleep(0) so that we inject an empty sleep instead of keeping the variable
        # empty as keeping it empty may trigger different, faster code paths.
        return payload.replace(f"({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})", "(0)")

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

    def measure_request_time(self, url: str, **kwargs: Dict[str, Any]) -> float:
        start = timer()
        try:
            if "headers" not in kwargs:
                self.forgiving_http_get(url)
            else:
                self.forgiving_http_get(url, headers=kwargs.get("headers"))
        except requests.exceptions.Timeout:
            return Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD

        return datetime.timedelta(seconds=timer() - start).seconds

    def contains_error(self, url: str, response: Optional[HTTPResponse]) -> str | None:
        if response is None:
            return None

        # 500 error code will not be matched as it's a significant source of FPs
        for message in SQL_ERROR_MESSAGES:
            if re.search(message, response.content):
                self.log.debug("Matched error: %s on %s", message, url)
                return message
        return None

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
    def create_data(message: Any) -> Dict[str, List[str] | dict[str, Any]]:
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
            f"sleep({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})",
            f"pg_sleep({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})",
            f"'||sleep({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})||'",
            f"'||pg_sleep({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})||'",
        ]
        sql_injection_error_payloads = ["'", '"']
        # Should be correct in all sql contexts: inside and outside strings, even after e.g. PHP addslashes()
        not_error_payload = "-1"
        message: List[Dict[str, Any]] = []

        # The code below may look complicated and repetitive, but it shows how the scanning logic works.
        for current_url in urls:
            for param_batch in more_itertools.batched(URL_PARAMS, 50):
                if self.is_url_with_parameters(current_url):
                    for error_payload in sql_injection_error_payloads:
                        url_with_payload = self.change_url_params(
                            url=current_url, payload=error_payload, param_batch=param_batch
                        )
                        url_without_payload = self.change_url_params(
                            url=current_url, payload=not_error_payload, param_batch=param_batch
                        )

                        error = self.contains_error(url_with_payload, self.forgiving_http_get(url_with_payload))

                        if (
                            not self.contains_error(url_without_payload, self.forgiving_http_get(url_without_payload))
                            and error
                        ):
                            message.append(
                                {
                                    "url": url_with_payload,
                                    "headers": {},
                                    "matched_error": error,
                                    "message": "It appears that this URL is vulnerable to SQL injection",
                                    "code": Statements.sql_injection.value,
                                }
                            )
                            if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                                return message

                    for sleep_payload in sql_injection_sleep_payloads:
                        url_with_no_sleep_payload = self.change_url_params(
                            url=current_url, payload=self.change_sleep_to_0(sleep_payload), param_batch=param_batch
                        )
                        url_with_sleep_payload = self.change_url_params(
                            url=current_url, payload=sleep_payload, param_batch=param_batch
                        )

                        flags = []
                        for _ in range(Config.Modules.SqlInjectionDetector.SQL_INJECTION_NUM_RETRIES_TIME_BASED):
                            # We explicitely want to re-check whether current URL is still time efficient
                            if (
                                self.measure_request_time(url_with_no_sleep_payload)
                                < Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD / 2
                                and self.measure_request_time(url_with_sleep_payload)
                                >= Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD
                            ):
                                flags.append(True)
                            else:
                                flags.append(False)
                                break

                        if all(flags):
                            message.append(
                                {
                                    "url": url_with_sleep_payload,
                                    "headers": {},
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
                    url_with_no_payload = self.create_url_with_batch_payload(
                        url=current_url, param_batch=param_batch, payload=not_error_payload
                    )

                    error = self.contains_error(url_with_payload, self.forgiving_http_get(url_with_payload))

                    if (
                        not self.contains_error(url_with_no_payload, self.forgiving_http_get(url_with_no_payload))
                        and error
                    ):
                        message.append(
                            {
                                "url": url_with_payload,
                                "headers": {},
                                "matched_error": error,
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
                    url_with_no_sleep_payload = self.create_url_with_batch_payload(
                        url=current_url, param_batch=param_batch, payload=self.change_sleep_to_0(sleep_payload)
                    )

                    for _ in range(Config.Modules.SqlInjectionDetector.SQL_INJECTION_NUM_RETRIES_TIME_BASED):
                        # We explicitely want to re-check whether current URL is still time efficient
                        if (
                            self.measure_request_time(url_with_no_sleep_payload)
                            < Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD / 2
                            and self.measure_request_time(url_with_sleep_payload)
                            >= Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD
                        ):
                            flags.append(True)
                        else:
                            flags.append(False)
                            break

                    if all(flags):
                        message.append(
                            {
                                "url": url_with_sleep_payload,
                                "headers": {},
                                "statement": "It appears that this URL is vulnerable to time-based SQL injection",
                                "code": Statements.sql_time_based_injection.value,
                            }
                        )
                        if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                            return message

            for error_payload in sql_injection_error_payloads:
                headers = self.create_headers(payload=error_payload)
                headers_no_payload = self.create_headers(payload=not_error_payload)

                error = self.contains_error(current_url, self.forgiving_http_get(current_url, headers=headers))

                if (
                    not self.contains_error(
                        current_url, self.forgiving_http_get(current_url, headers=headers_no_payload)
                    )
                    and error
                ):
                    message.append(
                        {
                            "url": current_url,
                            "headers": headers,
                            "matched_error": error,
                            "statement": "It appears that this URL is vulnerable to SQL injection through HTTP Headers",
                            "code": Statements.headers_sql_injection.value,
                            "headers": headers,
                        }
                    )
                    if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                        return message

            for sleep_payload in sql_injection_sleep_payloads:
                flags = []
                headers = self.create_headers(sleep_payload)
                headers_no_sleep_payload = self.create_headers(self.change_sleep_to_0(sleep_payload))

                for _ in range(Config.Modules.SqlInjectionDetector.SQL_INJECTION_NUM_RETRIES_TIME_BASED):
                    # We explicitely want to re-check whether current URL is still time efficient
                    if (
                        self.measure_request_time(current_url, headers=headers_no_sleep_payload)
                        < Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD / 2
                        and self.measure_request_time(current_url, headers=headers)
                        >= Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD
                    ):
                        flags.append(True)
                    else:
                        flags.append(False)
                        break

                if all(flags):
                    message.append(
                        {
                            "url": current_url,
                            "headers": headers,
                            "statement": "It appears that this URL is vulnerable to time-based SQL injection through HTTP Headers",
                            "code": Statements.headers_time_based_sql_injection.value,
                            "headers": headers,
                        }
                    )
                    if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                        return message

        return message

    def run(self, current_task: Task) -> None:
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

        message = self.scan(urls=links[: Config.Miscellaneous.MAX_URLS_TO_SCAN], task=current_task)

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
