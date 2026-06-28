from test.base import ArtemisModuleTestCase

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
