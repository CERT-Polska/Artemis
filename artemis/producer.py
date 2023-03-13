from typing import List, Optional

from karton.core import Producer, Task

from artemis.binds import TaskType
from artemis.db import DB

producer = Producer(identity="frontend")
db = DB()


def create_tasks(uris: List[str], tag: Optional[str] = None) -> None:
    for uri in uris:
        task = Task({"type": TaskType.NEW})
        task.add_payload("data", uri)
        if tag:
            task.add_payload("tag", tag, persistent=True)
        db.create_analysis(task)
        db.save_scheduled_task(task)
        producer.send_task(task)
