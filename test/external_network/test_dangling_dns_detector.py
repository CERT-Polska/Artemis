from test.base import ArtemisModuleTestCase
from unittest.mock import patch

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.modules.dangling_dns_detector import DanglingDnsDetector


class TestDanglingDnsDetectorIntegration(ArtemisModuleTestCase):
    karton_class = DanglingDnsDetector  # type: ignore

    def test_cname_dangling_real_domain(self) -> None:
        # given
        task = Task(
            {"type": TaskType.DOMAIN_THAT_MAY_NOT_EXIST.value},
            payload={
                "domain": "dangling-cname.test.artemis.lab.cert.pl",
                "last_domain": "dangling-cname.test.artemis.lab.cert.pl",
            },
        )

        # when
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list

        # then
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertTrue(
            "The defined domain has a CNAME record configured but the CNAME does not resolve."
            in call.kwargs["status_reason"],
        )

    def test_check_dns_ip_records_integration(self) -> None:
        # given
        task = Task(
            {"type": TaskType.DOMAIN_THAT_MAY_NOT_EXIST.value},
            payload={
                "domain": "dangling.test.artemis.lab.cert.pl",
                "last_domain": "dangling.test.artemis.lab.cert.pl",
            },
        )

        # when
        with patch("artemis.config.Config.Modules.DanglingDnsDetector") as mocked_config:
            mocked_config.DANGLING_DNS_NUMBER_OF_RETRIES_FOR_IP = 0
            self.run_task(task)
            (call,) = self.mock_db.save_task_result.call_args_list

        # then
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertTrue(
            "The defined domain has an A record configured but the IP does not resolve." in call.kwargs["status_reason"]
        )
