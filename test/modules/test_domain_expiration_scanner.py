import datetime
from test.base import ArtemisModuleTestCase
from unittest.mock import MagicMock, patch

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.modules.domain_expiration_scanner import DomainExpirationScanner


class TestDomainExpirationScanner(ArtemisModuleTestCase):
    karton_class = DomainExpirationScanner  # type: ignore

    @patch("artemis.modules.domain_expiration_scanner.perform_whois")
    def test_simple(self, mock_whois) -> None:  # type: ignore
        expiration = datetime.datetime.now() + datetime.timedelta(days=100)
        mock_domain = MagicMock()
        mock_domain.expiration_date = expiration
        mock_domain.name = "google.com"
        mock_whois.return_value = mock_domain

        task = Task(
            {"type": TaskType.DOMAIN.value},
            payload={"domain": "google.com"},
        )
        with patch("artemis.config.Config.Modules.DomainExpirationScanner") as mocked_config:
            mocked_config.DOMAIN_EXPIRATION_TIMEFRAME_DAYS = 5000
            self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertTrue(call.kwargs["status_reason"].startswith("Scanned domain will expire in"))
        self.assertIsInstance(call.kwargs["data"]["expiration_date"], datetime.datetime)
        mock_whois.assert_called_once_with(domain="google.com", logger=self.karton.log)
