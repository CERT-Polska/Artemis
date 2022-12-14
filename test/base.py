import os
import socket
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
        # We cannot use Artemis default DoH resolvers as they wouldn't be able to resolve
        # internal test services' addresses.
        self._ip_lookup_mock = patch(
            "artemis.request_limit.ip_lookup", MagicMock(side_effect=lambda host: {socket.gethostbyname(host)})
        )
        self._ip_lookup_mock.__enter__()

        self.mock_db = MagicMock()
        self.mock_db.contains_scheduled_task.return_value = False
        self.karton = self.karton_class(  # type: ignore
            config=ConfigMock(), backend=KartonBackendMockWithRedis(), db=self.mock_db
        )

    def tearDown(self) -> None:
        self._ip_lookup_mock.__exit__([])  # type: ignore
