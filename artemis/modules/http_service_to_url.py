#!/usr/bin/env python3
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class HTTPServiceToURL(ArtemisBase):
    """
    Converts HTTP SERVICE tasks to URL tasks for the service root URL so that the URLs can be consumed by other kartons
    that expect URLs (e.g. Nuclei).
    """

    identity = "http_service_to_url"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def _process(self, current_task: Task, url: str) -> None:
        content = self.http_get(url).content

        new_task = Task(
            {
                "type": TaskType.URL,
            },
            payload={
                "url": url,
                "content": content,
            },
        )
        self.add_task(current_task, new_task)
        self.db.save_task_result(task=current_task, status=TaskStatus.OK, data={"url": url, "content": content})

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        self.log.info(f"HTTPServiceToURL: {url}")

        self._process(current_task, url)


if __name__ == "__main__":
    HTTPServiceToURL().loop()
