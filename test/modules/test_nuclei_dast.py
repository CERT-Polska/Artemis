from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.nuclei_dast import NucleiDast


class NucleiDastTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = NucleiDast  # type: ignore

    def test_lfi_dast_template(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-flask-vulnerable-api",
                "path": "/files",
                "params": {"filename": "randomfilename"},
                "port": 5000,
            },
        )
        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(
            call.kwargs["status_reason"],
            "[high] http://test-flask-vulnerable-api:5000/files?filename=randomfilename: Local File Inclusion - Linux , [high] http://test-flask-vulnerable-api:5000/files?filename=randomfilename: Local File Inclusion - Linux ",
        )

    # def test_ssrf_dast_template(self) -> None:
    #     task = Task(
    #         {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    #         payload={
    #             "host": "test-flask-vulnerable-api",
    #             "path": "/ssrf",
    #             "params": {"url": "http://example.com"},
    #             "port": 5000,
    #         },
    #     )
    #     self.run_task(task)
    #     (call,) = self.mock_db.save_task_result.call_args_list
    #     self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
    #     self.assertEqual(
    #         call.kwargs["status_reason"],
    #         "[high] http://test-flask-vulnerable-api:5000/ssrf?url=http://example.com: SSRF - HTTP"
    #     )
