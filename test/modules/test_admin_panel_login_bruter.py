from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import TaskStatus, TaskType
from artemis.modules.admin_panel_login_bruter import AdminPanelLoginBruter


class AdminPanelLoginBruterTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = AdminPanelLoginBruter  # type: ignore

    def test_simple(self) -> None:
        sites = {
            "http://test-drupal-easy-password/user/login": ("admin", "admin"),
            "http://test-single-page-app-easy-password": ("admin", "admin1"),
        }

        for url, credentials in sites.items():
            username, password = credentials

            self.mock_db.reset_mock()
            task = Task(
                {"type": TaskType.URL},
                payload={"url": url},
            )
            self.run_task(task)
            (call,) = self.mock_db.save_task_result.call_args_list
            self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)
            self.assertEqual(
                call.kwargs["status_reason"],
                f"Found working credentials for {url}: username={username}, password={password}",
            )

            self.assertEqual(call.kwargs["data"], credentials)
