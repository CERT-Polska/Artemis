# type: ignore
from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.nosql_injection_detector import NoSqlInjectionDetector

TARGET_HOST = "test-express-with-nosql-injection"
TARGET = f"http://{TARGET_HOST}:3000"


class NoSqlInjectionDetectorTestCase(ArtemisModuleTestCase):
    karton_class = NoSqlInjectionDetector

    def test_nosql_injection_detector(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": TARGET_HOST, "port": 3000},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

        results = call.kwargs["data"]["result"]
        self.assertTrue(results)

        detected_parameters = set()
        for result in results:
            self.assertIn(f"{TARGET_HOST}:3000", result["url"])
            self.assertNotIn("/noisy", result["url"])
            self.assertNotIn("/not_vuln", result["url"])
            detected_parameters.update(result["parameters"])

        self.assertIn("q", detected_parameters)
        self.assertIn("id", detected_parameters)
        self.assertIn("username", detected_parameters)

        codes = {result["code"] for result in results}
        self.assertIn("nosql_injection", codes)
        self.assertIn("nosql_injection_json_body", codes)
        self.assertIn("nosql_injection_blind", codes)

    def test_json_body_probe_detects_login_endpoint(self) -> None:
        matched, completed = self.karton._probe_post(
            f"{TARGET}/api/login", ["username", "password"], "$artemisProbe", 1
        )
        self.assertTrue(completed)
        self.assertIsNotNone(matched)

    def test_noisy_endpoint_is_not_reported(self) -> None:
        matched, completed = self.karton._probe_get(f"{TARGET}/noisy", ["id"], "$artemisProbe", "1")
        self.assertTrue(completed)
        self.assertIsNone(matched)

    def test_not_vuln_endpoint_is_not_reported(self) -> None:
        matched, completed = self.karton._probe_get(f"{TARGET}/not_vuln", ["id"], "$artemisProbe", "1")
        self.assertTrue(completed)
        self.assertIsNone(matched)

    def test_error_probe_misses_error_swallowing_endpoint(self) -> None:
        matched, completed = self.karton._probe_get(f"{TARGET}/blind", ["q"], "$artemisProbe", "1")
        self.assertTrue(completed)
        self.assertIsNone(matched)

    def test_blind_probe_detects_error_swallowing_endpoint(self) -> None:
        matched, completed = self.karton._probe_boolean_get(f"{TARGET}/blind", ["q"])
        self.assertTrue(completed)
        self.assertIsNotNone(matched)

    def test_blind_probe_not_reported_on_coercing_endpoint(self) -> None:
        matched, completed = self.karton._probe_boolean_get(f"{TARGET}/not_vuln", ["q"])
        self.assertTrue(completed)
        self.assertIsNone(matched)

    def test_blind_probe_not_reported_on_noisy_endpoint(self) -> None:
        matched, completed = self.karton._probe_boolean_get(f"{TARGET}/noisy", ["id"])
        self.assertTrue(completed)
        self.assertIsNone(matched)

    def test_bracket_url_construction(self) -> None:
        url = self.karton._build_bracket_url(f"{TARGET}/search", ["id", "q"], "$ne", "1")
        self.assertEqual(url, f"{TARGET}/search?id[$ne]=1&q[$ne]=1")

    def test_baseline_operator_strips_dollar(self) -> None:
        self.assertEqual(self.karton._baseline_operator("$ne"), "ne")
        self.assertEqual(self.karton._baseline_operator("$artemisProbe"), "artemisProbe")

    def test_minimize_parameters_caps_and_falls_back(self) -> None:
        params = ["a", "b", "c"]
        minimal = self.karton.minimize_parameters(
            f"{TARGET}/not_vuln", params, self.karton._probe_get, "$artemisProbe", "1"
        )
        self.assertEqual(minimal, params)
