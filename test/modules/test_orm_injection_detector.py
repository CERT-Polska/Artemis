# type: ignore
from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.orm_injection_detector import OrmInjectionDetector


class OrmInjectionDetectorTestCase(ArtemisModuleTestCase):
    karton_class = OrmInjectionDetector

    def test_orm_injection_detector(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "test-django-with-orm-injection", "port": 8000},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        results = call.kwargs["data"]["result"]
        parameters = {result["parameter"] for result in results}

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        for result in call.kwargs["data"]["result"]:
            self.assertIn("test-django-with-orm-injection:8000", result["url"])

        self.assertIn("category__name", parameters)
        self.assertIn("content", parameters)
        self.assertIn("id", parameters)
        self.assertIn("title", parameters)

    def test_lookup_suffix_with_existing_lookup_param_preserves_siblings_and_baseline(self) -> None:
        original_url = (
            "http://test-django-with-orm-injection:8000/?category__name=Technology&creation_date__year__gte=2024"
        )
        matched = self.karton._test_lookup_suffix(original_url, "category__name", "__exact", "Technology")
        self.assertTrue(matched)

    def test_scan_with_raw_parameter_and_sibling_params(self) -> None:
        url = "http://test-django-with-orm-injection:8000/?category__name=Technology&creation_date__year__gte=2024"
        findings = self.karton.scan([url])
        self.assertTrue(findings)
        self.assertTrue(any(finding["url"] == url for finding in findings))
