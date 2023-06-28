import tempfile
from pathlib import Path

from test.base import ArtemisModuleTestCase

from jinja2 import BaseLoader, Environment, StrictUndefined
from karton.core import Task

from artemis.binds import Service, TaskType
from artemis.modules.bruter import Bruter
from artemis.reporting.base.language import Language
from artemis.reporting.base.reporters import reports_from_task_result
from artemis.reporting.base.templating import build_message_template
from artemis.reporting.export.translations import install_translations

environment = Environment(
    loader=BaseLoader(), extensions=["jinja2.ext.i18n"], undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True
)
with tempfile.NamedTemporaryFile() as f:
    install_translations(Language.en_US, environment, Path(f.name), Path("/dev/null"))

message_template_content = build_message_template()
message_template = environment.from_string(message_template_content)


class BruterAutoreporterIntegrationTest(ArtemisModuleTestCase):
    karton_class = Bruter  # type: ignore

    def test_sql_dumps(self) -> None:
        message = self._run_task_and_get_message("test-service-with-bruteable-files-sql-dumps")
        self.assertIn(
            "<li>The following files contain database dumps:",
            message,
        )
        self.assertIn(
            "http://test-service-with-bruteable-files-sql-dumps:80/localhost.sql",
            message,
        )

    def test_htpasswd(self) -> None:
        message = self._run_task_and_get_message("test-service-with-bruteable-files-htpasswd")
        self.assertIn(
            "<li>The following files contain passwords or password hashes:",
            message,
        )
        self.assertIn(
            "http://test-service-with-bruteable-files-htpasswd:80/_.htpasswd",
            message,
        )

    def _run_task_and_get_message(self, host: str) -> str:
        task = Task(
            {"type": TaskType.SERVICE, "service": Service.HTTP},
            payload={"host": host, "port": 80},
            payload_persistent={"original_domain": host},
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        data = {
            "created_at": None,
            "headers": {
                "receiver": "bruter",
            },
            "payload_persistent": {
                "original_domain": host,
            },
            "result": call.kwargs["data"],
        }

        reports = reports_from_task_result(data, Language.en_US)
        return message_template.render(
            {"data": {"contains_type": set([report.report_type for report in reports]), "reports": reports}}
        )
