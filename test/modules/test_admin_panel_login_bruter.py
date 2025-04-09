from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.admin_panel_login_bruter import AdminPanelLoginBruter


class AdminPanelLoginBruterTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = AdminPanelLoginBruter  # type: ignore

    def test_simple(self) -> None:
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-php-easy-admin-password",
                "port": 80,
            },
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
        self.assertEqual(call.kwargs["data"]["results"][0]["url"], "http://test-php-easy-admin-password:80/index.php")
        self.assertEqual(call.kwargs["data"]["results"][0]["username"], "admin")
        self.assertEqual(call.kwargs["data"]["results"][0]["password"], "admin")
        self.assertEqual(call.kwargs["data"]["results"][0]["indicators"], ["logout_link", "no_failure_messages"])
