import os
import tempfile
from pathlib import Path
from typing import List
from unittest.mock import MagicMock

from jinja2 import BaseLoader, Environment, StrictUndefined, Template
from karton.core import Task
from karton.core.test import BackendMock, ConfigMock, KartonTestCase
from redis import StrictRedis

from artemis.reporting.base.language import Language
from artemis.reporting.base.templating import build_message_template
from artemis.reporting.export.translations import install_translations


class KartonBackendMockWithRedis(BackendMock):
    def __init__(self) -> None:
        super().__init__()

        self.redis = StrictRedis(
            host=os.environ["TEST_REDIS_HOST"],
            port=int(os.environ["TEST_REDIS_PORT"]),
        )
        self.redis.flushall()

    def register_bind(self, *args) -> None:  # type: ignore
        pass

    def get_binds(self) -> List:  # type: ignore
        return []

    def iter_all_tasks(self, *args, **kwargs) -> List[Task]:  # type: ignore
        return []


class ArtemisModuleTestCase(KartonTestCase):
    def setUp(self) -> None:
        self.mock_db = MagicMock()
        self.mock_db.get_analysis_by_id.return_value = {}
        self.mock_db.contains_scheduled_task.return_value = False
        self.karton = self.karton_class(  # type: ignore
            config=ConfigMock(), backend=KartonBackendMockWithRedis(), db=self.mock_db
        )


class BaseReportingTest(ArtemisModuleTestCase):
    @staticmethod
    def generate_message_template() -> Template:
        environment = Environment(
            loader=BaseLoader(),
            extensions=["jinja2.ext.i18n"],
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        with tempfile.NamedTemporaryFile() as f:
            install_translations(Language.en_US, environment, Path(f.name), Path("/dev/null"))  # type: ignore
            message_template_content = build_message_template()
        return environment.from_string(message_template_content)
