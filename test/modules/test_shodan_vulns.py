from test.base import ArtemisModuleTestCase
from unittest import mock

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.modules.shodan_vulns import ShodanVulns


class ShodanVulnsTest(ArtemisModuleTestCase):
    karton_class = ShodanVulns

    def test_robots(self) -> None:
        task = Task(
            {"type": TaskType.IP},
            payload={
                TaskType.IP: "127.0.0.1",
            },
        )
        with mock.patch("shodan.Shodan.host", return_value={"vulns": ["CVE-2020-1938"]}):
            self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"], "Found vulnerabilities from Shodan API: CVE-2020-1938: tomcat_ghostcat"
        )
        self.assertEqual(call.kwargs["data"].critical_vulns, {"CVE-2020-1938": "tomcat_ghostcat"})
