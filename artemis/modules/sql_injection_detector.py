import datetime
import re
import urllib
import random
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from karton.core import Task

from artemis import http_requests
from artemis.binds import TaskStatus, TaskType, Service
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.karton_utils import check_connection_to_base_url_and_save_error
from artemis.module_base import ArtemisBase
from artemis.sql_messages_example import SQL_INJECTIONS, SQL_MESSAGES, URL_PARAMS
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
    def create_url_with_payload(url):
        selected_params = random.sample(URL_PARAMS, 30)
        assignments = {key: random.choice(SQL_INJECTIONS) for key in selected_params}
        url_to_scan = f"{url}?" + "&".join([f"{key}={value}" for key, value in assignments.items()])

        return url_to_scan

    @staticmethod
    def is_url_with_payload(url):
        if re.search("/?/*=", url):
            return True

    @staticmethod
    def change_url_params(url):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        params = list(query_params.keys())
        new_query_params = {}

        for param in params:
            new_query_params[param] = [random.choice(SQL_INJECTIONS)]

        new_query_string = urlencode(new_query_params, doseq=True)
        new_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query_string,
            parsed_url.fragment
        ))

        return new_url

    def create_url_to_scan(self, url):
        if self.is_url_with_payload(url):
            return self.change_url_params(url=url)
        else:
            return self.create_url_with_payload(url=url)

    @staticmethod
    def measure_time_request(url):
        start = datetime.datetime.now()
        response = http_requests.get(url)
        elapsed_time = (datetime.datetime.now() - start).seconds

        return elapsed_time, response

    @staticmethod
    def check_response_message(response):
        for message in SQL_MESSAGES:
            if re.search(message, response.content):
                return message

    def scan(self, urls, task):
        task_result = {
            "task_host": get_target_url(task),
            "status": task.status,
            "message": [],
        }

        for url in urls:
            url_to_scan = self.create_url_to_scan(url)
            elapsed_time, response_with_payload = self.measure_time_request(url_to_scan)
            response_message = self.check_response_message(response_with_payload)

            if response_message:
                task_result["message"].append(f"{url}: It appears that this url is vulnerable to SQL Injection")

            if elapsed_time > 1:
                task_result["message"].append(
                    f"{url}: The request is taking too long, it appears to be a Time-Based SQL Injection. You should check it out."
                )

            if response_with_payload.status_code == 500:
                task_result["message"].append(f"{url}: Response from server is equal to 500")

        task_result["message"] = list(set(task_result["message"]))
        return task_result

    def run(self, tasks: List[Task]) -> None:
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

            self.db.save_task_result(
                task=task, status=TaskStatus.INTERESTING, status_reason=", ".join(result.get("message")), data=links
            )


if __name__ == "__main__":
    SqlInjectionDetector().loop()
