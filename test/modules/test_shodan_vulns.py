from test.base import ArtemisModuleTestCase
from unittest import mock

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.modules.shodan_vulns import ShodanVulns


class ShodanVulnsTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = ShodanVulns  # type: ignore

    def test_robots(self) -> None:
        task = Task(
            {"type": TaskType.IP},
            payload={
                TaskType.IP: "127.0.0.1",
            },
        )
        with mock.patch("shodan.Shodan.host", return_value={"vulns": ["CVE-2020-1938", "CVE-1-1"]}):
            self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "Found vulnerabilities from Shodan API: CVE-1-1, CVE-2020-1938",
        )
        self.assertEqual(call.kwargs["data"].vulns, ["CVE-2020-1938", "CVE-1-1"])
