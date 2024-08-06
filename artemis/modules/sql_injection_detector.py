import datetime
import random
import re
import urllib
from timeit import default_timer as timer
from typing import Any, Dict, List, Optional
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
from artemis.sql_messages_example import SQL_ERROR_MESSAGES, URL_PARAMS
from artemis.task_utils import get_target_url


class SqlInjectionDetector(ArtemisBase):
    """
    Module for detecting sql Injection and Base Time Sql Injection vulnerabilities.
    """

    identity = "sql_injection_detector"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    @staticmethod
    def _strip_query_string(url: str) -> str:
        url_parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(url_parsed._replace(query="", fragment=""))

    @staticmethod
    def create_url_with_batch_payload(
        url: str, param_batch: Optional[tuple[Any]], sleep_payload: Optional[str] = None
    ) -> str:
        if param_batch is not None:
            assignments = {
                key: sleep_payload if sleep_payload else random.choice(Config.Modules.SqlInjectionDetector.PAYLOADS)
                for key in param_batch
            }
            url_with_payload = f"{url}?" + "&".join([f"{key}={value}" for key, value in assignments.items()])
            return unquote(url_with_payload)
        return url

    @staticmethod
    def is_url_with_payload(url: str) -> bool:
        if re.search("/?/*=", url):
            return True
        return False

    @staticmethod
    def change_url_params(url: str, sleep_payload: Optional[str] = None) -> str:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        params = list(query_params.keys())
        new_query_params = {}

        for param in params:
            new_query_params[param] = [
                sleep_payload if sleep_payload else random.choice(Config.Modules.SqlInjectionDetector.PAYLOADS)
            ]

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
        return unquote(new_url)

    @staticmethod
    def is_response_time_within_threshold(elapsed_time: float) -> bool:
        if elapsed_time < Config.Modules.SqlInjectionDetector.THRESHOLD:
            return True
        return False

    def are_requests_time_efficient(self, url: str) -> bool:
        start = timer()
        self.response_when_injecting(url)
        elapsed_time = datetime.timedelta(seconds=timer() - start).seconds

        flag = self.is_response_time_within_threshold(elapsed_time)

        return flag

    @staticmethod
    def contains_error(response: HTTPResponse) -> bool | None:
        for message in SQL_ERROR_MESSAGES:
            if re.search(message, response.content):
                return True
        return False

    @staticmethod
    def response_when_injecting(url: str) -> HTTPResponse:
        response = http_requests.get(url)

        return response

    def scan(self, urls: List[str], task: Task) -> Dict[str, object]:
        task_result = {
            "task_host": get_target_url(task),
            "status": task.status,
            "message": [],
        }
        message = []
        for current_url in urls:
            #  Below is the code describing the logic, but it is repetitive. What is better (create a universal
            #  function or leave it as below)
            if self.is_url_with_payload(current_url):
                url_with_payload = self.change_url_params(url=current_url)

                if not self.contains_error(self.response_when_injecting(current_url)) and self.contains_error(
                    self.response_when_injecting(url_with_payload)
                ):
                    message.append(f"{url_with_payload}: It appears that this url is vulnerable to SQL Injection")

                for sleep_payload in Config.Modules.SqlInjectionDetector.SLEEP_PAYLOAD:
                    url_with_sleep_payload = self.change_url_params(url=current_url, sleep_payload=sleep_payload)

                    if self.are_requests_time_efficient(current_url) and not self.are_requests_time_efficient(
                        url_with_sleep_payload
                    ):
                        message.append(
                            f"{url_with_sleep_payload}: It appears that this url is vulnerable to SQL Time Base Injection"
                        )
            else:
                for param_batch in more_itertools.batched(URL_PARAMS, 10):
                    url_with_payload = self.create_url_with_batch_payload(url=current_url, param_batch=param_batch)

                    if not self.contains_error(self.response_when_injecting(current_url)) and self.contains_error(
                        self.response_when_injecting(url_with_payload)
                    ):
                        message.append(f"{url_with_payload}: It appears that this url is vulnerable to SQL Injection")

                    for sleep_payload in Config.Modules.SqlInjectionDetector.SLEEP_PAYLOAD:
                        url_with_sleep_payload = self.create_url_with_batch_payload(
                            url=current_url, param_batch=param_batch, sleep_payload=sleep_payload
                        )

                        if self.are_requests_time_efficient(current_url) and not self.are_requests_time_efficient(
                            url_with_sleep_payload
                        ):
                            message.append(
                                f"{url_with_sleep_payload} It appears that this url is vulnerable to SQL Time Base Injection"
                            )
            if self.response_when_injecting(current_url).status_code == 500:
                message.append(f"{current_url}: Response from server is equal to 500")

        task_result["message"] = list(set(message))
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
                status_reason = str(message)
            else:
                status = TaskStatus.OK
                status_reason = None

            self.db.save_task_result(
                task=current_task, status=status, status_reason=status_reason, data={"result": message}
            )


if __name__ == "__main__":
    SqlInjectionDetector().loop()
