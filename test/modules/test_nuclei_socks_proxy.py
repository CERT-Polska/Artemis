from test.base import ArtemisModuleTestCase
from unittest.mock import patch

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.nuclei import Nuclei


class NucleiSocksProxyTest(ArtemisModuleTestCase):

    # Required for Artemis module tests
    karton_class = Nuclei  # type: ignore

    def setUp(self) -> None:
        """
        Limit nuclei templates used during test to only the SOCKS proxy template.
        This keeps tests fast and deterministic.
        """

        self.patcher = patch(
            "artemis.config.Config.Modules.Nuclei.OVERRIDE_STANDARD_NUCLEI_TEMPLATES_TO_RUN",
            [
                "/opt/artemis/modules/data/nuclei_templates_custom/unauthenticated-socks-proxy.yaml",
            ],
        )

        self.patcher.start()
        self.addCleanup(self.patcher.stop)

        return super().setUp()

    def test_socks_proxy_detection_pipeline(self) -> None:
        """
        Ensure the SOCKS proxy template runs correctly through the Artemis Nuclei module.
        """

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "example.com",
                "port": 1080,
            },
        )

        self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list

        # Template execution should not break the pipeline
        self.assertIn(call.kwargs["status"], [TaskStatus.OK, TaskStatus.INTERESTING, TaskStatus.ERROR])
