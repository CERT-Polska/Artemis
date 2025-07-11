import os
import tempfile
import urllib
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

from jinja2 import BaseLoader, Environment, StrictUndefined, Template
from karton.core import Task
from karton.core.test import BackendMock, ConfigMock, KartonTestCase
from redis import StrictRedis

from artemis.binds import Service, TaskType, WebApplication
from artemis.reporting.base.language import Language
from artemis.reporting.base.reporters import reports_from_task_result
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

    def obtain_webapp_task_result(self, receiver: str, webapp: WebApplication, url: str) -> Dict[str, Any]:
        domain = urllib.parse.urlparse(url).hostname
        task = Task(
            {"type": TaskType.WEBAPP, "webapp": webapp},
            payload={"url": url},
            payload_persistent={"original_domain": domain},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        return {
            "created_at": None,
            "headers": {
                "receiver": receiver,
            },
            "payload": {
                "url": url,
                "last_domain": domain,
            },
            "payload_persistent": {
                "original_domain": domain,
            },
            "result": call.kwargs["data"],
        }

    def obtain_http_task_result(self, receiver: str, host: str) -> Dict[str, Any]:
        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"host": host, "port": 80},
            payload_persistent={"original_domain": host},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        return {
            "created_at": None,
            "target_string": "http://" + host + ":80/",
            "headers": {
                "receiver": receiver,
            },
            "payload": {
                "last_domain": host,
            },
            "payload_persistent": {
                "original_domain": host,
            },
            "result": call.kwargs["data"],
        }

    def task_result_to_message(self, data: Dict[str, Any]) -> str:
        reports = reports_from_task_result(data, Language.en_US)  # type: ignore
        message_template = self.generate_message_template()
        return message_template.render(
            {
                "data": {
                    "custom_template_arguments": {},
                    "contains_type": set([report.report_type for report in reports]),
                    "reports": reports,
                }
            }
        )
