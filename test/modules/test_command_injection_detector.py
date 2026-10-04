# type: ignore
import re
import unittest
from test.base import ArtemisModuleTestCase
from unittest.mock import patch

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.command_injection_data import (
    INJECTION_TEMPLATES,
    build_output_payloads,
    build_time_payloads,
)
from artemis.http_requests import HTTPResponse
from artemis.modules.command_injection_detector import CommandInjectionDetector


class CommandInjectionDataTestCase(unittest.TestCase):
    def test_output_marker_requires_execution_not_reflection(self) -> None:
        payloads = build_output_payloads()
        self.assertEqual(len(payloads), len(INJECTION_TEMPLATES))

        for injection, marker in payloads:
            # The injection carries the literal arithmetic expression, not the marker itself.
            self.assertIn("$((", injection)
            self.assertNotIn(marker, injection)

            # Reflection: echoing the raw injection back does not produce the marker.
            self.assertNotIn(marker, f"<html>reflected: {injection}</html>")

            # Execution: evaluating $((a*b)) the way a shell would makes the marker appear.
            executed = re.sub(
                r"\$\(\((\d+)\*(\d+)\)\)",
                lambda m: str(int(m.group(1)) * int(m.group(2))),
                injection,
            )
            self.assertIn(marker, executed)

    def test_output_markers_are_unique_per_pair(self) -> None:
        markers = [marker for _, marker in build_output_payloads()]
        self.assertEqual(len(markers), len(set(markers)))

    def test_time_payloads_carry_sleep_and_neutralize(self) -> None:
        sleep_payloads = build_time_payloads(5)
        self.assertEqual(len(sleep_payloads), len(INJECTION_TEMPLATES))
        self.assertTrue(all("sleep 5" in payload for payload in sleep_payloads))

        baseline_payloads = build_time_payloads(0)
        self.assertTrue(all("sleep 0" in payload for payload in baseline_payloads))


class CommandInjectionDetectorHelperTestCase(ArtemisModuleTestCase):
    karton_class = CommandInjectionDetector

    def test_change_sleep_to_0(self) -> None:
        self.assertEqual(self.karton.change_sleep_to_0("; sleep 5"), "; sleep 0")
        self.assertEqual(self.karton.change_sleep_to_0("$(sleep 5)"), "$(sleep 0)")
        self.assertEqual(self.karton.change_sleep_to_0("`sleep 5`"), "`sleep 0`")

    def test_response_contains_marker(self) -> None:
        response = HTTPResponse(
            status_code=200,
            content_bytes=b"prefix ABC123DEF suffix",
            encoding="utf-8",
            is_redirect=False,
            url="http://example.com",
            headers={},
        )
        self.assertTrue(self.karton.response_contains_marker(response, "ABC123DEF"))
        self.assertFalse(self.karton.response_contains_marker(response, "notpresent"))
        self.assertFalse(self.karton.response_contains_marker(None, "ABC123DEF"))


class CommandInjectionDetectorIntegrationTestCase(ArtemisModuleTestCase):
    karton_class = CommandInjectionDetector

    def test_command_injection_detector(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "test-apache-with-command-injection.local", "port": 80},
        )

        with patch("artemis.config.Config.Modules.CommandInjectionDetector") as mocked_config:
            mocked_config.COMMAND_INJECTION_STOP_ON_FIRST_MATCH = False
            mocked_config.COMMAND_INJECTION_MINIMAL_PARAMS_MAX_LEN = 5
            mocked_config.COMMAND_INJECTION_TIME_THRESHOLD = 5
            mocked_config.COMMAND_INJECTION_NUM_RETRIES_TIME_BASED = 2
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        status_reason = call.kwargs["status_reason"]

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

        # Output-based: the execution-proving marker came back, so the shell ran the injected echo.
        # The reported URL carries a per-request random marker, so it is matched on endpoint +
        # statement rather than in full.
        self.assertIn("It appears that this URL is vulnerable to OS command injection", status_reason)
        self.assertIn("http://test-apache-with-command-injection.local/ping.php?host=", status_reason)

        # Time-based blind: the injected sleep produced a reproducible delay. This URL is deterministic
        # after minimization, so match it in full (endpoint, vulnerable parameter, and statement).
        self.assertIn(
            "http://test-apache-with-command-injection.local/ping.php?host=; sleep 5: "
            "It appears that this URL is vulnerable to time-based (blind) OS command injection",
            status_reason,
        )

        # The safe endpoint only reflects input without running it, so it must never be reported —
        # the reflected payload surfaces the literal arithmetic, never its evaluated result.
        self.assertNotIn("safe.php", status_reason)
