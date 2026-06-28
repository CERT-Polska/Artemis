from test.base import ArtemisModuleTestCase
from unittest.mock import patch

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.reverse_dns_lookup import ReverseDNSLookup


class ReverseDNSLookupTest(ArtemisModuleTestCase):
    karton_class = ReverseDNSLookup  # type: ignore

    @patch(
        "artemis.modules.reverse_dns_lookup.gethostbyaddr", return_value=("students.mimuw.edu.pl", [], ["193.0.96.129"])
    )
    def test_simple(self, mock_gethostbyaddr) -> None:  # type: ignore
        task = Task(
            {"type": TaskType.IP},
            payload={TaskType.IP: "193.0.96.129"},
            payload_persistent={"original_domain": "mimuw.edu.pl"},
        )
        results = self.run_task(task)

        expected_task = Task(
            {"type": TaskType.NEW, "origin": ReverseDNSLookup.identity},
            payload={"data": "students.mimuw.edu.pl"},
            payload_persistent={"original_domain": "mimuw.edu.pl"},
        )
        del results[0].payload["created_at"]
        self.assertTasksEqual(results, [expected_task])
        mock_gethostbyaddr.assert_called_once_with("193.0.96.129")
