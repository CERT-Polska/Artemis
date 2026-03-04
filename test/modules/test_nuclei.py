from test.base import ArtemisModuleTestCase
from unittest.mock import patch

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.nuclei import Nuclei


class NucleiShortTemplateListTest(ArtemisModuleTestCase):
    # Tests with template list shortened to speed up test runtime

    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = Nuclei  # type: ignore

    def setUp(self) -> None:
        # list of templates used in tests
        self.patcher = patch(
            "artemis.config.Config.Modules.Nuclei.OVERRIDE_STANDARD_NUCLEI_TEMPLATES_TO_RUN",
            [
                "http/cves/2020/CVE-2020-28976.yaml",
            ],
        )
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

        return super().setUp()

    def test_interactsh(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-mock-CVE-2020-28976",
                "port": 80,
            },
            payload_persistent={
                "module_runtime_configurations": {"nuclei": {"severity_threshold": "medium_and_above"}}
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertRegex(
            call.kwargs["status_reason"],
            r"\[medium\] http://test-php-mock-CVE-2020-28976:80/wp-content/plugins/canto/includes/lib/get\.php\?subdomain=[a-z0-9\.]+: WordPress Canto 1\.3\.0 - Blind Server-Side Request Forgery WordPress Canto plugin 1\.3\.0 is susceptible to blind server-side request forgery\. An attacker can make a request to any internal and external server via /includes/lib/detail\.php\?subdomain and thereby possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site\.",
        )
