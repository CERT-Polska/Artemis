import re
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Sequence

import more_itertools
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import get_injectable_parameters, get_links_to_scan
from artemis.http_requests import HTTPResponse
from artemis.injection_utils import (
    change_url_params,
    create_url_with_batch_payload,
    has_query_parameters,
    measure_request_time,
    minimize_parameters,
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

    def create_url_with_batch_payload(self, url: str, param_batch: Sequence[str], payload: str) -> str:
        return create_url_with_batch_payload(url=url, param_batch=param_batch, payload=payload)

    @staticmethod
    def change_sleep_to_0(payload: str) -> str:
        # This is to replace sleep(5) with sleep(0) so that we inject an empty sleep instead of keeping the variable
        # empty as keeping it empty may trigger different, faster code paths.
        return payload.replace(f"({Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD})", "(0)")

    @staticmethod
    def is_url_with_parameters(url: str) -> bool:
        return has_query_parameters(url)

    @staticmethod
    def change_url_params(url: str, payload: str, param_batch: Sequence[str]) -> str:
        return change_url_params(url=url, payload=payload, param_batch=param_batch)

    def measure_request_time(self, url: str, **kwargs: Dict[str, Any]) -> float:
        headers = kwargs.get("headers")  # type: ignore
        return measure_request_time(
            http_get_func=self.forgiving_http_get,
            url=url,
            timeout_threshold=Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD,
            headers=headers,
        )

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
            return self.change_url_params(url=url, payload=payload, param_batch=param_batch)
        return self.create_url_with_batch_payload(url=url, param_batch=param_batch, payload=payload)

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

        if minimization_mode == "error":
            payload_without_effect = baseline_payload if baseline_payload is not None else ""
        else:
            payload_without_effect = self.change_sleep_to_0(payload)

        def test_param(param: str) -> bool:
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
                return bool(not self.contains_error(url_without, self.forgiving_http_get(url_without)) and error)
            else:
                return bool(
                    self.measure_request_time(url_without)
                    < Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD / 2
                    and self.measure_request_time(url_with)
                    >= Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD
                )

        minimal_params = minimize_parameters(
            params=params,
            test_func=test_param,
            max_len=Config.Modules.SqlInjectionDetector.SQL_INJECTION_MINIMAL_PARAMS_MAX_LEN,
        )

        if minimal_params != params:
            mode_label = "error-based" if minimization_mode == "error" else "time-based"
            self.log.info(
                "SQLi %s parameter minimization: %s -> %s",
                mode_label,
                params,
                minimal_params,
            )

        return minimal_params

    @staticmethod
    def create_headers(payload: str) -> dict[str, str]:
        headers = {}
        for key, value in HEADERS.items():
            headers.update({key: value + payload})
        return headers

    def minimize_headers(
        self,
        url: str,
        headers: Dict[str, str],
        payload: str,
        minimization_mode: Literal["error", "time"],
        baseline_payload: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Try to find the minimal set of headers that still triggers SQLi. Currently minimizes to single headers only.
        Falls back to original headers if none work individually. When minimized headers are found,
        the result is capped to SQL_INJECTION_MINIMAL_HEADERS_MAX_LEN.
        """
        if minimization_mode == "error" and baseline_payload is None:
            raise ValueError("baseline_payload is required for error-based minimization")

        minimal_headers: Dict[str, str] = {}
        if minimization_mode == "error":
            payload_without_effect = baseline_payload if baseline_payload is not None else ""
        else:
            payload_without_effect = self.change_sleep_to_0(payload)

        for header_name, header_value in headers.items():
            single_header = {header_name: header_value}
            no_effect_header = {header_name: HEADERS[header_name] + payload_without_effect}

            if minimization_mode == "error":
                error = self.contains_error(url, self.forgiving_http_get(url, headers=single_header))
                if not self.contains_error(url, self.forgiving_http_get(url, headers=no_effect_header)) and error:
                    minimal_headers[header_name] = header_value
            elif (
                self.measure_request_time(url, headers=no_effect_header)
                < Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD / 2
                and self.measure_request_time(url, headers=single_header)
                >= Config.Modules.SqlInjectionDetector.SQL_INJECTION_TIME_THRESHOLD
            ):
                minimal_headers[header_name] = header_value
            if len(minimal_headers) >= Config.Modules.SqlInjectionDetector.SQL_INJECTION_MINIMAL_HEADERS_MAX_LEN:
                break

        if minimal_headers:
            mode_label = "error-based" if minimization_mode == "error" else "time-based"
            self.log.info(
                "SQLi %s header minimization: %s -> %s",
                mode_label,
                list(headers.keys()),
                list(minimal_headers.keys()),
            )
            return minimal_headers

        # fallback if no single header triggers SQLi
        return headers

    @staticmethod
    def create_status_reason(message: Any) -> str:
        status_reason = []
        for injection_message in message:
            base_reason = f"{injection_message.get('url')}: {injection_message.get('statement')}"

            headers_used = injection_message.get("headers")
            if headers_used:
                headers_text = ", ".join([f"{k}: {v}" for k, v in headers_used.items()])
                base_reason += f" (Headers used: {headers_text})"

            status_reason.append(base_reason)
        return ", ".join(set(status_reason))

    @staticmethod
    def create_data(message: Any) -> Dict[str, List[str] | dict[str, Any]]:
        new_message = []
        for item in message:
            if item not in new_message:
                new_message.append(item)

        data = {
            "result": new_message,
            "statements": {
                "sql_injection": Statements.sql_injection.value,
                "sql_time_based_injection": Statements.sql_time_based_injection.value,
                "headers_sql_injection": Statements.headers_sql_injection.value,
                "headers_time_based_sql_injection": Statements.headers_time_based_sql_injection.value,
            },
        }
        return data  # type: ignore

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
                            minimal_params = self.minimize_parameters(
                                url=current_url,
                                params=list(param_batch),
                                payload=error_payload,
                                baseline_payload=not_error_payload,
                                use_change_url_params=True,
                                minimization_mode="error",
                            )
                            minimal_url = self.change_url_params(
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
                            minimal_params = self.minimize_parameters(
                                url=current_url,
                                params=list(param_batch),
                                payload=sleep_payload,
                                use_change_url_params=True,
                                minimization_mode="time",
                            )
                            minimal_url = self.change_url_params(
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
                        minimal_params = self.minimize_parameters(
                            url=current_url,
                            params=list(param_batch),
                            payload=error_payload,
                            baseline_payload=not_error_payload,
                            use_change_url_params=False,
                            minimization_mode="error",
                        )
                        minimal_url = self.create_url_with_batch_payload(
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
                        minimal_params = self.minimize_parameters(
                            url=current_url,
                            params=list(param_batch),
                            payload=sleep_payload,
                            use_change_url_params=False,
                            minimization_mode="time",
                        )
                        minimal_url = self.create_url_with_batch_payload(
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
                    minimal_headers = self.minimize_headers(
                        url=current_url,
                        headers=headers,
                        payload=error_payload,
                        baseline_payload=not_error_payload,
                        minimization_mode="error",
                    )
                    message.append(
                        {
                            "url": current_url,
                            "headers": minimal_headers,
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
                    minimal_headers = self.minimize_headers(
                        url=current_url,
                        headers=headers,
                        payload=sleep_payload,
                        minimization_mode="time",
                    )
                    message.append(
                        {
                            "url": current_url,
                            "headers": minimal_headers,
                            "statement": "It appears that this URL is vulnerable to time-based SQL injection through HTTP Headers",
                            "code": Statements.headers_time_based_sql_injection.value,
                        }
                    )
                    if Config.Modules.SqlInjectionDetector.SQL_INJECTION_STOP_ON_FIRST_MATCH:
                        return message

        return message

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        links = get_links_to_scan(url)

        message = self.scan(urls=links, task=current_task)

        if message:
            status = TaskStatus.INTERESTING
            status_reason = self.create_status_reason(message=message)
        else:
            status = TaskStatus.OK
            status_reason = None

        data = self.create_data(message=message)

        self.save_task_result(task=current_task, status=status, status_reason=status_reason, data=data)


if __name__ == "__main__":
    SqlInjectionDetector.parallel_loop()
