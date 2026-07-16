import datetime
import random
import urllib
from enum import Enum
from timeit import default_timer as timer
from typing import Any, Dict, List, Literal, Optional

import more_itertools
import requests
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.command_injection_data import build_output_payloads, build_time_payloads
from artemis.config import Config
from artemis.crawling import (
    crawl_and_filter,
    get_injectable_parameters,
)
from artemis.http_requests import HTTPResponse
from artemis.module_base import ArtemisBase
from artemis.modules.data.parameters import URL_PARAMS
from artemis.modules.data.static_extensions import STATIC_EXTENSIONS
from artemis.task_utils import get_target_url


class Statements(Enum):
    command_injection = "command_injection"
    command_injection_time_based = "command_injection_time_based"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.HIGH)
class CommandInjectionDetector(ArtemisBase):
    """
    Module for detecting output-based and time-based (blind) OS command injection vulnerabilities.
    """

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "command_injection_detector"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    # Batch parameters so each injected URL stays under this budget (artemis.http_requests rejects
    # URLs of 2000+ chars); the echo-marker payload is long, so a fixed count could overflow.
    MAX_INJECTED_URL_LENGTH = 1900

    @staticmethod
    def _strip_query_string(url: str) -> str:
        url_parsed = urllib.parse.urlparse(url)
        return urllib.parse.urlunparse(url_parsed._replace(query="", fragment=""))

    @staticmethod
    def _url_with_payload(url: str, params: tuple[Any, ...], payload: str) -> str:
        separator = "&" if "?" in url else "?"
        assignments = "&".join(f"{name}={payload}" for name in params)
        return f"{url}{separator}{assignments}"

    @staticmethod
    def change_sleep_to_0(payload: str) -> str:
        # Neutralize `sleep 5` to `sleep 0` so the time-based baseline injects an equivalent but
        # non-delaying command.
        return payload.replace(
            f"sleep {Config.Modules.CommandInjectionDetector.COMMAND_INJECTION_TIME_THRESHOLD}", "sleep 0"
        )

    @staticmethod
    def response_contains_marker(response: Optional[HTTPResponse], marker: str) -> bool:
        if response is None:
            return False
        return marker in response.content

    def measure_request_time(self, url: str) -> float:
        start = timer()
        try:
            self.forgiving_http_get(url)
        except requests.exceptions.Timeout:
            return Config.Modules.CommandInjectionDetector.COMMAND_INJECTION_TIME_THRESHOLD
        return datetime.timedelta(seconds=timer() - start).seconds

    def _confirm_time_based(self, url_with_sleep: str, url_without_sleep: str) -> bool:
        # Re-check across several rounds that the injected sleep is slow and its neutralized baseline
        # is fast; a single fluke round is enough to reject the candidate (kills timing false positives).
        threshold = Config.Modules.CommandInjectionDetector.COMMAND_INJECTION_TIME_THRESHOLD
        for _ in range(Config.Modules.CommandInjectionDetector.COMMAND_INJECTION_NUM_RETRIES_TIME_BASED):
            if not (
                self.measure_request_time(url_without_sleep) < threshold / 2
                and self.measure_request_time(url_with_sleep) >= threshold
            ):
                return False
        return True

    def _minimize_parameters(
        self,
        url: str,
        params: List[str],
        payload: str,
        minimization_mode: Literal["output", "time"],
        marker: Optional[str] = None,
    ) -> List[str]:
        """
        Find the minimal set of parameters that still proves the injection, capped at
        COMMAND_INJECTION_MINIMAL_PARAMS_MAX_LEN. Falls back to the full set if none prove it alone.
        """
        threshold = Config.Modules.CommandInjectionDetector.COMMAND_INJECTION_TIME_THRESHOLD
        baseline_payload = self.change_sleep_to_0(payload) if minimization_mode == "time" else ""

        minimal_params: List[str] = []
        for param in params:
            if minimization_mode == "output":
                assert marker is not None  # required for output-based minimization
                confirmed = self.response_contains_marker(
                    self.forgiving_http_get(self._url_with_payload(url, (param,), payload)), marker
                )
            else:
                confirmed = (
                    self.measure_request_time(self._url_with_payload(url, (param,), baseline_payload)) < threshold / 2
                    and self.measure_request_time(self._url_with_payload(url, (param,), payload)) >= threshold
                )
            if confirmed:
                minimal_params.append(param)
            if len(minimal_params) >= Config.Modules.CommandInjectionDetector.COMMAND_INJECTION_MINIMAL_PARAMS_MAX_LEN:
                break
        return minimal_params or params

    def scan(self, urls: List[str], task: Task) -> List[Dict[str, Any]]:
        self.log.info("Scanning URLs: %s", urls)
        message: List[Dict[str, Any]] = []

        for current_url in urls:
            parameters = get_injectable_parameters(current_url)
            self.log.info("Obtained parameters: %s for url %s", parameters, current_url)

            output_payloads = build_output_payloads()
            time_payloads = build_time_payloads(
                Config.Modules.CommandInjectionDetector.COMMAND_INJECTION_TIME_THRESHOLD
            )
            max_payload_len = max(
                [len(injection) for injection, _ in output_payloads] + [len(payload) for payload in time_payloads]
            )

            # Group parameters so each injected URL (base + "&name=payload" per param) stays under the
            # length budget; strict=False keeps a single over-budget parameter in its own batch.
            for param_batch in more_itertools.constrained_batches(
                parameters + URL_PARAMS,
                max_size=self.MAX_INJECTED_URL_LENGTH - len(current_url),
                get_len=lambda name: len(name) + max_payload_len + 2,
                strict=False,
            ):
                # Output-based: the marker appears in the response only if the shell evaluated the
                # injected arithmetic, so a match proves execution rather than reflection.
                for injection, expected_marker in output_payloads:
                    injected_url = self._url_with_payload(current_url, param_batch, injection)
                    if self.response_contains_marker(self.forgiving_http_get(injected_url), expected_marker):
                        self.log.info("Matched command injection: %s on %s", injection, current_url)
                        minimal_params = self._minimize_parameters(
                            current_url,
                            list(param_batch),
                            injection,
                            minimization_mode="output",
                            marker=expected_marker,
                        )
                        message.append(
                            {
                                "url": self._url_with_payload(current_url, tuple(minimal_params), injection),
                                "statement": "It appears that this URL is vulnerable to OS command injection",
                                "code": Statements.command_injection.value,
                            }
                        )
                        if Config.Modules.CommandInjectionDetector.COMMAND_INJECTION_STOP_ON_FIRST_MATCH:
                            return message

                # Time-based blind: confirm a reproducible delay against the sleep-neutralized baseline.
                for sleep_payload in time_payloads:
                    url_with_sleep = self._url_with_payload(current_url, param_batch, sleep_payload)
                    url_without_sleep = self._url_with_payload(
                        current_url, param_batch, self.change_sleep_to_0(sleep_payload)
                    )
                    if self._confirm_time_based(url_with_sleep, url_without_sleep):
                        self.log.info("Matched time-based command injection: %s on %s", sleep_payload, current_url)
                        minimal_params = self._minimize_parameters(
                            current_url, list(param_batch), sleep_payload, minimization_mode="time"
                        )
                        message.append(
                            {
                                "url": self._url_with_payload(current_url, tuple(minimal_params), sleep_payload),
                                "statement": "It appears that this URL is vulnerable to time-based (blind) "
                                "OS command injection",
                                "code": Statements.command_injection_time_based.value,
                            }
                        )
                        if Config.Modules.CommandInjectionDetector.COMMAND_INJECTION_STOP_ON_FIRST_MATCH:
                            return message

        return message

    @staticmethod
    def create_status_reason(message: Any) -> str:
        return ", ".join(sorted({f"{item.get('url')}: {item.get('statement')}" for item in message}))

    def create_data(self, message: Any) -> Dict[str, Any]:
        deduplicated_message = []
        for item in message:
            if item not in deduplicated_message:
                deduplicated_message.append(item)

        return {
            "result": deduplicated_message,
            "statements": {
                "command_injection": Statements.command_injection.value,
                "command_injection_time_based": Statements.command_injection_time_based.value,
            },
        }

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)

        links = crawl_and_filter(url)
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
    CommandInjectionDetector.parallel_loop()
