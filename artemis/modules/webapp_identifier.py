#!/usr/bin/env python3
import re
from typing import List, Tuple

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType, WebApplication
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url

WEBAPP_SIGNATURES: List[Tuple[WebApplication, str]] = [
    (WebApplication.WORDPRESS, '<meta name="generator" content="WordPress'),
    (WebApplication.JOOMLA, '<meta name="generator" content="Joomla!'),
    (WebApplication.DRUPAL, '<meta name="generator" content="Drupal'),
    (WebApplication.EZPUBLISH, '<meta name="generator" content="eZ Publish'),
    (WebApplication.TYPESETTER, '<meta name="generator" content="Typesetter CMS'),
    (WebApplication.ROUNDCUBE, "Copyright \\(C\\) The Roundcube Dev Team"),
    (WebApplication.MOODLE, '<meta name="keywords" content="moodle,'),
]


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class WebappIdentifier(ArtemisBase):
    """
    Tries to identify the web application and produces a WEBAPP task with proper type (e.g. WebApplication.WORDPRESS).
    """

    identity = "webapp_identifier"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _identify(self, url: str) -> WebApplication:
        response = self.http_get(url, allow_redirects=True)

        for webapp_id, webapp_sig in WEBAPP_SIGNATURES:
            if re.search(webapp_sig, response.text, re.IGNORECASE):
                return webapp_id

        if "/wp-includes/css/" in response.text:
            return WebApplication.WORDPRESS

        # Detect WordPress not advertising itself in generator
        response = self.http_get(f"{url}/license.txt", allow_redirects=True)
        if response.text.startswith("WordPress - Web publishing software"):
            return WebApplication.WORDPRESS

        return WebApplication.UNKNOWN

    def _process(self, current_task: Task, url: str) -> None:
        application = self._identify(url)

        new_task = Task(
            {
                "type": TaskType.WEBAPP,
                "webapp": application,
            },
            payload={
                "url": url,
            },
        )
        self.add_task(current_task, new_task)

        self.db.save_task_result(task=current_task, status=TaskStatus.OK, data=application)

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"application identifier scanning {url}")

        self._process(current_task, url)


if __name__ == "__main__":
    WebappIdentifier().loop()
