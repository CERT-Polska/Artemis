import datetime
from test.base import ArtemisModuleTestCase
from unittest.mock import patch

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.modules.domain_expiration_scanner import DomainExpirationScanner


class TestDomainExpirationScanner(ArtemisModuleTestCase):
    karton_class = DomainExpirationScanner  # type: ignore

    def test_simple(self) -> None:
        task = Task(
            {"type": TaskType.DOMAIN.value},
            payload={"domain": "google.com"},
        )

        with patch("artemis.config.Config.Modules.DomainExpirationScanner") as mocked_config:
            mocked_config.DOMAIN_EXPIRATION_TIMEFRAME_DAYS = 5000
            self.run_task(task)

            (call,) = self.mock_db.save_task_result.call_args_list
            self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
            reason = call.kwargs["status_reason"]
            self.assertTrue(reason.startswith("Scanned domain will expire in"))
            self.assertTrue(isinstance(call.kwargs["data"]["expiration_date"], datetime.datetime))
