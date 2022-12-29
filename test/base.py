import os
import socket
from typing import List
from unittest.mock import MagicMock, patch

from karton.core.test import ConfigMock, KartonBackendMock, KartonTestCase
from redis import StrictRedis


class KartonBackendMockWithRedis(KartonBackendMock):
    def __init__(self) -> None:
        super().__init__()

        self.redis = StrictRedis(
            host=os.environ["TEST_REDIS_HOST"],
            port=int(os.environ["TEST_REDIS_PORT"]),
        )
        self.redis.flushall()


class ArtemisModuleTestCase(KartonTestCase):
    def setUp(self) -> None:
        # Unfortunately, in the context of a test that is about to run and a respective module has already been
        # imported, to mock ip_lookup we need to mock it in modules it has been imported to,
        # so we need to enumerate the locations it's used in in the list below.
        for item in ["artemis.request_limit.ip_lookup", "artemis.modules.port_scanner.ip_lookup"]:
            # We cannot use Artemis default DoH resolvers as they wouldn't be able to resolve
            # internal test services' addresses.
            self._ip_lookup_mock = patch(item, MagicMock(side_effect=lambda host: {socket.gethostbyname(host)}))
            self._ip_lookup_mock.__enter__()

        def mock_get_top_values_for_statistic(name: str, count: int) -> List[str]:
            if name == "bruter":
                return ["config.dist"]
            raise NotImplementedError()

        self.mock_db = MagicMock()
        self.mock_db.get_top_values_for_statistic = mock_get_top_values_for_statistic
        self.mock_db.contains_scheduled_task.return_value = False
        self.karton = self.karton_class(  # type: ignore
            config=ConfigMock(), backend=KartonBackendMockWithRedis(), db=self.mock_db
        )

    def tearDown(self) -> None:
        self._ip_lookup_mock.__exit__([])  # type: ignore
