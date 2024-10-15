# type: ignore
from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskType
from artemis.modules.dalfox import DalFox


class DalFoxTestCase(ArtemisModuleTestCase):
    karton_class = DalFox

    def test_dalfox_run_on_index_page(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.UNKNOWN.value},
            payload={"url": "http://test_apache-with-xss"},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        self.assertIsNotNone(call.kwargs["status_reason"])
        self.assertEqual(call.kwargs["status"], "INTERESTING")
        self.assertTrue(len(call.kwargs["data"]["result"]) >= 1)
        self.assertEqual(call.kwargs["task"].payload["url"], "http://test_apache-with-xss")

        unique_values_list = []
        for result_single_data in call.kwargs["data"]["result"]:
            unique_values_list.append((result_single_data.get("param"), result_single_data.get("type")))
            self.assertEqual(result_single_data.get("url").split("?")[0], "http://test_apache-with-xss/")
        self.assertEqual(len(unique_values_list), len(set(unique_values_list)))
