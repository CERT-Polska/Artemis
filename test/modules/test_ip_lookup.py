from test.base import ArtemisModuleTestCase
from unittest.mock import patch

from karton.core import Task

from artemis.binds import TaskType
from artemis.modules.ip_lookup import IPLookup


class IPLookupTest(ArtemisModuleTestCase):
    karton_class = IPLookup  # type: ignore

    @patch("artemis.modules.ip_lookup.lookup", return_value={"146.59.80.63"})
    def test_simple(self, mock_lookup) -> None:  # type: ignore
        task = Task(
            {"type": TaskType.DOMAIN},
            payload={TaskType.DOMAIN.value: "lebihan.pl"},
        )
        results = self.run_task(task)

        expected_task = Task(
            {"type": TaskType.NEW, "origin": IPLookup.identity},
            payload={"data": "146.59.80.63", "last_domain": "lebihan.pl"},
        )
        del results[0].payload["created_at"]
        self.assertTasksEqual(results, [expected_task])
        mock_lookup.assert_called_once_with("lebihan.pl")
