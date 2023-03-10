from typing import List

from karton.core import Producer, Task

from artemis.binds import TaskType
from artemis.db import DB

producer = Producer(identity="frontend")
db = DB()


def create_tasks(tag: str, uris: List[str]) -> None:
    for uri in uris:
        task = Task({"type": TaskType.NEW})
        task.add_payload("data", uri)
        task.add_payload("tag", tag, persistent=True)
        db.create_analysis(task)
        db.save_scheduled_task(task)
        producer.send_task(task)
