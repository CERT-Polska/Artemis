from typing import List, Optional

from karton.core import Producer, Task
from karton.core.task import TaskPriority

from artemis.binds import TaskType
from artemis.db import DB

producer = Producer(identity="frontend")
db = DB()


def create_tasks(
    uris: List[str],
    tag: Optional[str] = None,
    disabled_modules: List[str] = [],
    priority: Optional[TaskPriority] = None,
    requests_per_second_override: Optional[float] = None,
) -> None:
    for uri in uris:
        task = Task({"type": TaskType.NEW})
        task.add_payload("data", uri)
        if priority:
            task.priority = priority
        if tag:
            task.add_payload("tag", tag, persistent=True)
        if requests_per_second_override:
            task.add_payload("requests_per_second_override", requests_per_second_override, persistent=True)
        task.add_payload("disabled_modules", ",".join(disabled_modules), persistent=True)
        db.create_analysis(task)
        db.save_scheduled_task(task)
        db.save_tag(tag)
        producer.send_task(task)
