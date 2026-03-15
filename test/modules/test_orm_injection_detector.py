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
            payload={"host": "test-flask-with-orm-injection", "port": 5000},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertTrue(len(call.kwargs["data"]["result"]) > 0)

        # Verify at least one finding has the expected structure
        finding = call.kwargs["data"]["result"][0]
        self.assertIn("url", finding)
        self.assertIn("parameter", finding)
        self.assertIn("suffix", finding)
        self.assertIn("code", finding)

    def test_orm_injection_safe_endpoint(self) -> None:
        """The safe endpoint should not trigger ORM injection findings when
        only safe parameters are present in crawled links."""
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "test-flask-with-orm-injection", "port": 5000},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        # Check that findings are from /search, not /safe
        for finding in call.kwargs["data"]["result"]:
            self.assertNotIn("/safe", finding["url"])
