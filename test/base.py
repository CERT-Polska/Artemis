import os
from unittest.mock import MagicMock

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
        self.mock_db = MagicMock()
        self.mock_db.contains_scheduled_task.return_value = False
        self.karton = self.karton_class(  # type: ignore
            config=ConfigMock(), backend=KartonBackendMockWithRedis(), db=self.mock_db
        )
