# type: ignore
from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.lfi_detector import LFIDetector


class LFIDetectorTestCase(ArtemisModuleTestCase):
    karton_class = LFIDetector

    def test_lfi_detector(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={"host": "test-apache-with-lfi", "port": 80},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        print(call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["status_reason"], "todo")
