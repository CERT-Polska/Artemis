# type: ignore
from test.base import ArtemisModuleTestCase
from unittest.mock import patch

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.lfi_detector import LFIDetector


class LFIDetectorTestCase(ArtemisModuleTestCase):
    karton_class = LFIDetector

    def test_lfi_detector_with_rce(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "test-apache-with-lfi-and-rce", "port": 80},
        )

        with patch("artemis.config.Config.Modules.LFIDetector") as mocked_config:
            mocked_config.LFI_STOP_ON_FIRST_MATCH = False
            mocked_config.LFI_MINIMAL_PARAMS_MAX_LEN = 5
            self.run_task(task)
            (call,) = self.mock_db.save_task_result.call_args_list

            self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
            self.assertIn(
                "It appears that this URL is vulnerable to LFI: " "http://test-apache-with-lfi-and-rce:80/page.php?id=",
                call.kwargs["status_reason"],
            )

            self.assertIn(
                "etc/passwd",
                call.kwargs["status_reason"],
            )
            self.assertIn(
                "It appears that this URL is vulnerable to RCE: " "http://test-apache-with-lfi-and-rce:80/page.php?id=",
                call.kwargs["status_reason"],
            )

            self.assertIn(
                "%0a/bin/cat%20/etc/passwd",
                call.kwargs["status_reason"],
            )


class LFIParameterMinimizationTestCase(ArtemisModuleTestCase):
    karton_class = LFIDetector

    def test_minimize_parameters_caps(self) -> None:
        params = ["a", "b", "c", "d", "e", "f", "g"]

        def mocked_create_url(url: str, param_batch: list[str], payload: str) -> str:
            return f"{param_batch[0]}::{payload}"

        def mocked_indicator(_original_response: object, response: object) -> str | None:
            param_name = str(response).split("::", maxsplit=1)[0]
            if param_name in {"a", "b", "c", "d", "e", "f"}:
                return "/etc/passwd"
            return None

        with patch("artemis.config.Config.Modules.LFIDetector") as mocked_config:
            mocked_config.LFI_MINIMAL_PARAMS_MAX_LEN = 5
            with patch("artemis.modules.lfi_detector.create_url_with_batch_payload", side_effect=mocked_create_url):
                with patch.object(self.karton, "http_get", side_effect=lambda test_url: test_url):
                    with patch.object(self.karton, "contains_lfi_indicator", side_effect=mocked_indicator):
                        minimal_params = self.karton.minimize_parameters(
                            url="http://example.com/login",
                            params=params,
                            payload="../../etc/passwd",
                            original_response=object(),
                        )

        self.assertEqual(minimal_params, ["a", "b", "c", "d", "e"])
