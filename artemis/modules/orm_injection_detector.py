import random
import re
import urllib
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlencode, urlparse, urlunparse

import more_itertools
from karton.core import Task
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import (
    get_injectable_parameters,
    get_links_and_resources_on_same_domain,
)
from artemis.http_requests import HTTPResponse
from artemis.module_base import ArtemisBase
from artemis.modules.data.parameters import URL_PARAMS
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.orm_injection_data import HEADERS, ORM_ERROR_MESSAGES
from artemis.task_utils import get_target_url

class Statements(Enum):
    orm_injection = "orm_injection"
    headers_orm_injection = "headers_orm_injection"

class OrmInjectionDetector(ArtemisBase):
    """
    Module for detecting error-based ORM injection vulnerabilities.
    """
    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "orm_injection_detector"
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
        if re.search(r"/?/*=", url):
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
        concatenation = "&" if OrmInjectionDetector.is_url_with_parameters(new_url) else "?"
        new_url = f"{new_url}" + concatenation + "&".join([f"{key}={value}" for key, value in assignments.items()])
        return unquote(new_url)

    def contains_error(self, url: str, response: Optional[HTTPResponse]) -> Optional[str]:
        if response is None:
            return None

        for message in ORM_ERROR_MESSAGES:
            if re.search(message, response.content):
                self.log.debug("Matched ORM error: %s on %s", message, url)
                return message
        return None

    @staticmethod
    def create_headers(payload: str) -> Dict[str, str]:
        headers = {}
        for key, value in HEADERS.items():
            headers.update({key: value + payload})
        return headers

    @staticmethod
    def create_status_reason(message: Any) -> str:
        status_reason = []
        for injection_message in message:
            status_reason.append(f"{injection_message.get('url')}: {injection_message.get('message')}")
        return ", ".join(set(status_reason))

    @staticmethod
    def create_data(message: Any) -> Dict[str, Any]:
        message = list(more_itertools.unique_everseen(message))
        return {
            "result": message,
            "statements": {
                "orm_injection": Statements.orm_injection.value,
                "headers_orm_injection": Statements.headers_orm_injection.value,
            },
        }

    def scan(self, urls: List[str], task: Task) -> List[Dict[str, Any]]:
        self.log.info("Scanning URLs: %s", urls)

        orm_injection_error_payloads = ["\"'", "')", "\"]}"]
        not_error_payload = "-1"
        message: List[Dict[str, Any]] = []

        for current_url in urls:
            parameters = get_injectable_parameters(current_url)
            self.log.info("Obtained parameters: %s for url %s", parameters, current_url)

            for param_batch in more_itertools.batched(parameters + URL_PARAMS, 75):
                if self.is_url_with_parameters(current_url):
                    for error_payload in orm_injection_error_payloads:
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
                                    "message": "It appears that this URL is vulnerable to ORM injection",
                                    "code": Statements.orm_injection.value,
                                }
                            )
                            if Config.Modules.OrmInjectionDetector.ORM_INJECTION_STOP_ON_FIRST_MATCH:
                                return message

                for error_payload in orm_injection_error_payloads:
                    url_with_payload = self.create_url_with_batch_payload(
                        url=current_url, param_batch=param_batch, payload=error_payload
                    )
                    url_with_no_payload = self.create_url_with_batch_payload(
                        url=current_url, param_batch=param_batch, payload=not_error_payload
                    )

                    error = self.contains_error(url_with_payload, self.forgiving_http_get(url_with_payload))

                    if not self.contains_error(url_with_no_payload, self.forgiving_http_get(url_with_no_payload)) and error:
                        message.append(
                            {
                                "url": url_with_payload,
                                "headers": {},
                                "matched_error": error,
                                "message": "It appears that this URL is vulnerable to ORM injection",
                                "code": Statements.orm_injection.value,
                            }
                        )
                        if Config.Modules.OrmInjectionDetector.ORM_INJECTION_STOP_ON_FIRST_MATCH:
                            return message

            for error_payload in orm_injection_error_payloads:
                headers = self.create_headers(payload=error_payload)
                headers_no_payload = self.create_headers(payload=not_error_payload)

                error = self.contains_error(current_url, self.forgiving_http_get(current_url, headers=headers))

                if (
                    not self.contains_error(current_url, self.forgiving_http_get(current_url, headers=headers_no_payload))
                    and error
                ):
                    message.append(
                        {
                            "url": current_url,
                            "headers": headers,
                            "matched_error": error,
                            "message": "It appears that this URL is vulnerable to ORM injection through HTTP Headers",
                            "code": Statements.headers_orm_injection.value,
                        }
                    )
                    if Config.Modules.OrmInjectionDetector.ORM_INJECTION_STOP_ON_FIRST_MATCH:
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
    OrmInjectionDetector().loop()
