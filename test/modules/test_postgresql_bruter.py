from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.postgresql_bruter import PostgreSQLBruter


class PostgreSQLBruterTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = PostgreSQLBruter  # type: ignore

    def test_simple(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.POSTGRESQL},
            payload={"host": "test-postgresql-with-easy-password", "port": 5432},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"], "Found working credentials for the PostgreSQL server: example:example"
        )
        self.assertEqual(call.kwargs["data"].credentials, [("example", "example")])
