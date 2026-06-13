from test.base import ArtemisModuleTestCase
from typing import NamedTuple

from karton.core import Task

from artemis.binds import Service, TaskType, WebApplication
from artemis.modules.webapp_identifier import WebappIdentifier


class TestData(NamedTuple):
    domain: str
    application: WebApplication


class WebappIdentifierTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = WebappIdentifier  # type: ignore

    def test_simple(self) -> None:
        data = [
            TestData("test-old-joomla", WebApplication.JOOMLA),
            TestData("test-old-wordpress", WebApplication.WORDPRESS),
        ]

        for entry in data:
            task = Task(
                {"type": TaskType.SERVICE, "service": Service.HTTP},
                payload={"host": entry.domain, "port": 80},
            )

            result = self.run_task(task)

            webapp_tasks = [t for t in result if t.headers["type"] == TaskType.WEBAPP]

            self.assertEqual(len(webapp_tasks), 1)
            webapp_task = webapp_tasks[0]
            self.assertEqual(webapp_task.headers["webapp"], entry.application)
            self.assertEqual(webapp_task.payload["url"], f"http://{entry.domain}:80")

            technology_tags = webapp_task.payload["technology_tags"]
            self.assertIsInstance(technology_tags, list)
            self.assertGreater(len(technology_tags), 0)
            for tag in technology_tags:
                self.assertIsInstance(tag, str)

            # The full structured technology list is carried on the WEBAPP task payload;
            # cve_lookup reads it from there instead of from a separate task type.
            technologies = webapp_task.payload["technologies"]
            self.assertIsInstance(technologies, list)
            self.assertGreater(len(technologies), 0)
            for tech in technologies:
                self.assertIsInstance(tech, dict)
                self.assertIn("name", tech)
                self.assertIn("version", tech)
                self.assertIn("cpe", tech)
                self.assertIn("categories", tech)
                self.assertIsInstance(tech["categories"], list)

            # Be specific: the CMS must show up in the detected technologies (a regression that
            # stops detecting it should fail here), and at least one technology must carry a CPE
            # since that is exactly what cve_lookup needs downstream to query NVD.
            detected_names = {str(tech["name"]).lower() for tech in technologies}
            self.assertIn(entry.application.value, detected_names)
            self.assertTrue(any(tech["cpe"] for tech in technologies))
