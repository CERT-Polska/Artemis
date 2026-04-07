import datetime
import re
from enum import Enum
from timeit import default_timer as timer
from typing import Any, Dict, List, Literal, Optional

import more_itertools
import requests
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import get_injectable_parameters
from artemis.http_requests import HTTPResponse
from artemis.injection_utils import (
    change_url_params,
    collect_urls_to_scan,
    create_scan_result_data,
    create_status_reason,
    create_url_with_batch_payload,
    is_url_with_parameters,
)
from artemis.module_base import ArtemisBase
from artemis.modules.data.parameters import URL_PARAMS
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

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "sql_injection_detector"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    @staticmethod
    def change_sleep_to_0(payload: str) -> str:
        # This is to replace sleep(5) with sleep(0) so that we inject an empty sleep instead of keeping the variable
        # empty as keeping it empty may trigger different, faster code paths.
        return payload.replace(f"({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})", "(0)")

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

    def _create_injected_url(
        self, url: str, payload: str, param_batch: tuple[Any, ...], use_change_url_params: bool
    ) -> str:
        if use_change_url_params:
            return change_url_params(url=url, payload=payload, param_batch=param_batch)
        return create_url_with_batch_payload(url=url, param_batch=param_batch, payload=payload)

    def minimize_parameters(
        self,
        url: str,
        params: List[str],
        payload: str,
        use_change_url_params: bool,
        minimization_mode: Literal["error", "time"],
        baseline_payload: Optional[str] = None,
    ) -> List[str]:
        """
        Try to find the minimal set of parameters that still triggers SQLi. Currently minimizes to single parameters only.
        Falls back to original params if none work individually. When minimized parameters are found,
        the result is capped to SQL_INJECTION_MINIMAL_PARAMS_MAX_LEN.
        """
        if minimization_mode == "error" and baseline_payload is None:
            raise ValueError("baseline_payload is required for error-based minimization")

        minimal_params: List[str] = []
        if minimization_mode == "error":
            payload_without_effect = baseline_payload if baseline_payload is not None else ""
        else:
            payload_without_effect = self.change_sleep_to_0(payload)

        for param in params:
            single_batch = (param,)
            url_with = self._create_injected_url(
                url=url, payload=payload, param_batch=single_batch, use_change_url_params=use_change_url_params
            )
            url_without = self._create_injected_url(
                url=url,
                payload=payload_without_effect,
                param_batch=single_batch,
                use_change_url_params=use_change_url_params,
            )

            if minimization_mode == "error":
                error = self.contains_error(url_with, self.forgiving_http_get(url_with))
                if not self.contains_error(url_without, self.forgiving_http_get(url_without)) and error:
                    minimal_params.append(param)
                continue

            if (
                self.measure_request_time(url_without)
                < Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD / 2
                and self.measure_request_time(url_with)
                >= Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD
            ):
                minimal_params.append(param)

        if minimal_params:
            capped_minimal_params = minimal_params[
                : Config.Modules.SqlInjectionDetector.SQL_INJECTION_MINIMAL_PARAMS_MAX_LEN
            ]
            mode_label = "error-based" if minimization_mode == "error" else "time-based"
            self.log.info(
                "SQLi %s parameter minimization: %s -> %s",
                mode_label,
                params,
                capped_minimal_params,
            )
            return capped_minimal_params

        # fallback if no single param triggers SQLi
        return params

    @staticmethod
    def create_headers(payload: str) -> dict[str, str]:
        headers = {}
        for key, value in HEADERS.items():
            headers.update({key: value + payload})
        return headers

    def scan(self, urls: List[str], task: Task) -> List[Dict[str, Any]]:
        self.log.info("Scanning URLs: %s", urls)

        sql_injection_sleep_payloads = [
            f"sleep({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})",
            f"pg_sleep({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})",
            f"'||sleep({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})||'",
            f"'||pg_sleep({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})||'",
        ]
        sql_injection_error_payloads = ["'\""]
        # Should be correct in all sql contexts: inside and outside strings, even after e.g. PHP addslashes()
        not_error_payload = "-1"
        message: List[Dict[str, Any]] = []

        # The code below may look complicated and repetitive, but it shows how the scanning logic works.
        for current_url in urls:
            parameters = get_injectable_parameters(current_url)
            self.log.info("Obtained parameters: %s for url %s", parameters, current_url)

            for param_batch in more_itertools.batched(parameters + URL_PARAMS, 75):
                if is_url_with_parameters(current_url):
                    for error_payload in sql_injection_error_payloads:
                        url_with_payload = change_url_params(
                            url=current_url, payload=error_payload, param_batch=param_batch
                        )
                        url_without_payload = change_url_params(
                            url=current_url, payload=not_error_payload, param_batch=param_batch
                        )

                        error = self.contains_error(url_with_payload, self.forgiving_http_get(url_with_payload))

                        if (
                            not self.contains_error(url_without_payload, self.forgiving_http_get(url_without_payload))
                            and error
                        ):
                            minimal_params = self.minimize_parameters(
                                url=current_url,
                                params=list(param_batch),
                                payload=error_payload,
                                baseline_payload=not_error_payload,
                                use_change_url_params=True,
                                minimization_mode="error",
                            )
                            minimal_url = change_url_params(
                                url=current_url, payload=error_payload, param_batch=tuple(minimal_params)
                            )
                            message.append(
                                {
                                    "url": minimal_url,
                                    "headers": {},
                                    "matched_error": error,
                                    "statement": "It appears that this URL is vulnerable to SQL injection",
                                    "code": Statements.sql_injection.value,
                                }
                            )
                            if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                                return message

                    for sleep_payload in sql_injection_sleep_payloads:
                        url_with_no_sleep_payload = change_url_params(
                            url=current_url, payload=self.change_sleep_to_0(sleep_payload), param_batch=param_batch
                        )
                        url_with_sleep_payload = change_url_params(
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
                            minimal_params = self.minimize_parameters(
                                url=current_url,
                                params=list(param_batch),
                                payload=sleep_payload,
                                use_change_url_params=True,
                                minimization_mode="time",
                            )
                            minimal_url = change_url_params(
                                url=current_url, payload=sleep_payload, param_batch=tuple(minimal_params)
                            )
                            message.append(
                                {
                                    "url": minimal_url,
                                    "headers": {},
                                    "statement": "It appears that this URL is vulnerable to time-based SQL injection",
                                    "code": Statements.sql_time_based_injection.value,
                                }
                            )
                            if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                                return message

                for error_payload in sql_injection_error_payloads:
                    url_with_payload = create_url_with_batch_payload(
                        url=current_url, param_batch=param_batch, payload=error_payload
                    )
                    url_with_no_payload = create_url_with_batch_payload(
                        url=current_url, param_batch=param_batch, payload=not_error_payload
                    )

                    error = self.contains_error(url_with_payload, self.forgiving_http_get(url_with_payload))

                    if (
                        not self.contains_error(url_with_no_payload, self.forgiving_http_get(url_with_no_payload))
                        and error
                    ):
                        minimal_params = self.minimize_parameters(
                            url=current_url,
                            params=list(param_batch),
                            payload=error_payload,
                            baseline_payload=not_error_payload,
                            use_change_url_params=False,
                            minimization_mode="error",
                        )
                        minimal_url = create_url_with_batch_payload(
                            url=current_url, param_batch=tuple(minimal_params), payload=error_payload
                        )
                        message.append(
                            {
                                "url": minimal_url,
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
                    url_with_sleep_payload = create_url_with_batch_payload(
                        url=current_url, param_batch=param_batch, payload=sleep_payload
                    )
                    url_with_no_sleep_payload = create_url_with_batch_payload(
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
                        minimal_params = self.minimize_parameters(
                            url=current_url,
                            params=list(param_batch),
                            payload=sleep_payload,
                            use_change_url_params=False,
                            minimization_mode="time",
                        )
                        minimal_url = create_url_with_batch_payload(
                            url=current_url, param_batch=tuple(minimal_params), payload=sleep_payload
                        )
                        message.append(
                            {
                                "url": minimal_url,
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
                        }
                    )
                    if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                        return message

        return message

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)

        links = collect_urls_to_scan(url)

        message = self.scan(urls=links, task=current_task)
        message = list(more_itertools.unique_everseen(message))

        if message:
            status = TaskStatus.INTERESTING
            status_reason = create_status_reason(message)
        else:
            status = TaskStatus.OK
            status_reason = None

        data = create_scan_result_data(message, Statements)

        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=data)


if __name__ == "__main__":
    SqlInjectionDetector().loop()
