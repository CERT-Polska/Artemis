#!/usr/bin/env python3
import re
from typing import List, Tuple

import requests
from karton.core import Task

from artemis.binds import Application, Service, TaskStatus, TaskType
from artemis.module_base import ArtemisHTTPBase

WEBAPP_SIGNATURES: List[Tuple[Application, str]] = [
    (Application.WORDPRESS, '<meta name="generator" content="WordPress'),
    (Application.JOOMLA, '<meta name="generator" content="Joomla!'),
    (Application.DRUPAL, '<meta name="generator" content="Drupal'),
    (Application.EZPUBLISH, '<meta name="generator" content="eZ Publish'),
    (Application.TYPESETTER, '<meta name="generator" content="Typesetter CMS'),
    (Application.ROUNDCUBE, "Copyright \\(C\\) The Roundcube Dev Team"),
    (Application.MOODLE, '<meta name="keywords" content="moodle,'),
    (Application.IDRAC, "<title>Dell Remote Access Controller 5</title>"),
    (Application.IDRAC, "- iDRAC[6-8] -"),
]


class WebappIdentifier(ArtemisHTTPBase):
    """
    Tries to identify the webapp
    """

    identity = "webapp_identifier"
    filters = [
        {"type": TaskType.SERVICE, "service": Service.HTTP},
    ]

    @staticmethod
    def _identify(url: str) -> Application:
        response = requests.get(url, verify=False, allow_redirects=True, timeout=5)

        for webapp_id, webapp_sig in WEBAPP_SIGNATURES:
            if re.search(webapp_sig, response.text):
                return webapp_id

        # Detect WordPress not advertising itself in generator
        response = requests.get(f"{url}/license.txt", verify=False, allow_redirects=True, timeout=5)
        if response.text.startswith("WordPress - Web publishing software"):
            return Application.WORDPRESS

        return Application.UNKNOWN

    def _process(self, current_task: Task, url: str) -> Tuple[str, Application]:
        application = self._identify(url)

        if application != Application.UNKNOWN:
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

    def run(self, current_task: Task) -> None:  # type: ignore
        url = self.get_target_url(current_task)
        self.log.info(f"application identifier scanning {url}")

        self._process(current_task, url)


if __name__ == "__main__":
    WebappIdentifier().loop()
