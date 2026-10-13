from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.modules.joomla_extensions import JoomlaExtensions


class JoomlaExtensionsTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = JoomlaExtensions  # type: ignore

    def test_detect_and_compare(self) -> None:
        task = Task(
            {"type": TaskType.WEBAPP, "webapp": WebApplication.JOOMLA},
            payload={"url": "http://test-joomla-with-extensions/"},
        )
        self.run_task(task)

        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

        extensions = call.kwargs["data"]["extensions"]
        outdated = call.kwargs["data"]["outdated"]

        by_key = {e["key"]: e for e in extensions}
        self.assertEqual(set(by_key), {"com_slideshowck", "com_attachments", "mod_slideshowck"})

        self.assertEqual(by_key["com_attachments"]["version"], "4.2.4")
        self.assertEqual(by_key["com_attachments"]["latest_version"], "6")
        self.assertTrue(by_key["com_attachments"]["outdated"])

        self.assertEqual(by_key["com_slideshowck"]["version"], "2.9.6")
        self.assertFalse(by_key["com_slideshowck"]["outdated"])

        self.assertEqual(by_key["mod_slideshowck"]["name"], "Slideshow CK")
        self.assertFalse(by_key["mod_slideshowck"]["outdated"])

        self.assertNotIn("com_content", by_key)

        self.assertEqual(outdated, ["com_attachments"])
        self.assertIn("Outdated Joomla! extension: com_attachments", call.kwargs["status_reason"])
