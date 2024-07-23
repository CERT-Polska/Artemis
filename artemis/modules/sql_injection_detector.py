import datetime
import random
import re
import urllib
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from karton.core import Task

from artemis import http_requests
from artemis.binds import Service, TaskStatus, TaskType
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.http_requests import HTTPResponse
from artemis.karton_utils import check_connection_to_base_url_and_save_error
from artemis.module_base import ArtemisBase
from artemis.sql_messages_example import PAYLOADS, SQL_ERROR_MESSAGES, URL_PARAMS
from artemis.task_utils import get_target_url


class SqlInjectionDetector(ArtemisBase):
    """
    An Artemis module that search sql.

    """

    # Module name that will be displayed
    identity = "sql_injection_detector"

    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    @staticmethod
    def _strip_query_string(url: str) -> str:
        url_parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(url_parsed._replace(query="", fragment=""))

    @staticmethod
    def create_url_with_payload(url: str, sleep_payload: str | None = None) -> str:
        selected_params = random.sample(URL_PARAMS, 30)
        assignments = {key: sleep_payload if sleep_payload else random.choice(PAYLOADS) for key in selected_params}
        url_with_payload = f"{url}?" + "&".join([f"{key}={value}" for key, value in assignments.items()])

        return url_with_payload

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
            new_query_params[param] = [sleep_payload if sleep_payload else random.choice(PAYLOADS)]

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

        return new_url

    def create_url_to_scan(self, url: str, sleep_payload: Optional[str] = None) -> str:
        if self.is_url_with_payload(url):
            return self.change_url_params(url=url, sleep_payload=sleep_payload)
        else:
            return self.create_url_with_payload(url=url, sleep_payload=sleep_payload)

    def response_lt_1(self, url: str, sleep_payload: Optional[str] = None) -> bool:
        if_elapsed_time_gt_1 = []
        for i in range(3):
            start = datetime.datetime.now()
            self.response_when_injecting(self.create_url_to_scan(url=url, sleep_payload=sleep_payload))
            elapsed_time = (datetime.datetime.now() - start).seconds

            if_elapsed_time_gt_1.append(True) if elapsed_time < 1 else if_elapsed_time_gt_1.append(False)

        return True if all(if_elapsed_time_gt_1) else False

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
        for url_without_payload in urls:
            url_with_payload = self.create_url_to_scan(url_without_payload)

            if not self.contains_error(self.response_when_injecting(url_without_payload)) and self.contains_error(
                self.response_when_injecting(url_with_payload)
            ):
                print("is instance list? ", isinstance(task_result["message"], list))
                message.append(f"{url_without_payload}: It appears that this url is vulnerable to SQL Injection")

            if self.response_lt_1(url_without_payload) and not self.response_lt_1(
                url_without_payload, sleep_payload="'||pg_sleep(1)'||"
            ):
                message.append(
                    f"{url_without_payload}: It appears that this url is vulnerable to SQL Time Base Injection"
                )

            if self.response_when_injecting(url_without_payload).status_code == 500:
                message.append(f"{url_without_payload}: Response from server is equal to 500")

        task_result["message"] = message
        return task_result

    def run_multiple(self, tasks: List[Task]) -> None:
        tasks = [task for task in tasks if check_connection_to_base_url_and_save_error(self.db, task)]
        self.log.info(f"running on {len(tasks)} hosts.")

        links = []

        links_per_task = {}
        for task in tasks:
            url = get_target_url(task)
            links = get_links_and_resources_on_same_domain(url)
            links.append(url)
            links_per_task[task.uid] = list(set(links) | set([self._strip_query_string(link) for link in links]))
            links.extend(links_per_task[task.uid])

        for task in tasks:
            result = self.scan(urls=links_per_task[task.uid], task=task)
            message = str(result["message"])
            self.db.save_task_result(task=task, status=TaskStatus.INTERESTING, status_reason=message, data=links)


if __name__ == "__main__":
    SqlInjectionDetector().loop()
