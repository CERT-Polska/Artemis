import os
import socket
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from jinja2 import BaseLoader, Environment, StrictUndefined, Template
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


class ArtemisModuleTestCase(KartonTestCase):
    def setUp(self) -> None:
        # Unfortunately, in the context of a test that is about to run and a respective module has already been
        # imported, to mock lookup we need to mock it in modules it has been imported to,
        # so we need to enumerate the locations it's used in in the list below.
        for item in ["artemis.module_base.lookup", "artemis.modules.port_scanner.lookup"]:
            # We cannot use Artemis default DoH resolvers as they wouldn't be able to resolve
            # internal test services' addresses.
            self._lookup_mock = patch(item, MagicMock(side_effect=lambda host: {socket.gethostbyname(host)}))
            self._lookup_mock.__enter__()

        self.mock_db = MagicMock()
        self.mock_db.get_analysis_by_id.return_value = {}
        self.mock_db.contains_scheduled_task.return_value = False
        self.karton = self.karton_class(  # type: ignore
            config=ConfigMock(), backend=KartonBackendMockWithRedis(), db=self.mock_db
        )

    def tearDown(self) -> None:
        sys.stderr.write("a\n")
        self._lookup_mock.__exit__([])  # type: ignore
        sys.stderr.write("b\n")


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
            install_translations(Language.en_US, environment, Path(f.name), Path("/dev/null"))
            message_template_content = build_message_template()
        return environment.from_string(message_template_content)
