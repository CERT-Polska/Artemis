import traceback
from abc import abstractmethod
from typing import Optional, cast

import requests
from karton.core import Karton, Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.db import DB
from artemis.redis_cache import RedisCache
from artemis.resource_lock import ResourceLock

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


class ArtemisBase(Karton):
    """
    Artemis base module. Provides helpers (such as e.g. cache) for all modules.
    """

    def __init__(self, db: Optional[DB] = None, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.cache = RedisCache(self.backend.redis, self.identity)
        self.lock = ResourceLock(self.backend.redis, self.identity)
        if db:
            self.db = db
        else:
            self.db = DB()

    def get_target(self, current_task: Task) -> str:
        task_type = current_task.headers["type"]

        if task_type == TaskType.SERVICE:
            return current_task.get_payload("host")

        if task_type == TaskType.DOMAIN:
            return current_task.get_payload(TaskType.DOMAIN)

        if task_type == TaskType.IP:
            return current_task.get_payload(TaskType.IP)

        raise ValueError("Unknown target found")

    def add_task(self, current_task: Task, new_task: Task) -> None:
        new_task.root_uid = current_task.root_uid
        if self.db.save_scheduled_task(new_task):
            self.send_task(new_task)

    @abstractmethod
    def run(self, current_task: Task) -> None:
        raise NotImplementedError()

    def process(self, *args) -> None:
        current_task = cast(Task, args[0])
        try:
            self.run(current_task)
        except Exception:
            self.db.save_task_result(task=current_task, status=TaskStatus.ERROR, data=traceback.format_exc())
            raise


class ArtemisHTTPBase(ArtemisBase):
    def get_target_url(self, current_task: Task) -> str:
        assert current_task.headers["service"] == Service.HTTP

        target = self.get_target(current_task)
        port = current_task.get_payload("port")
        protocol = "http"
        if current_task.get_payload("ssl"):
            protocol += "s"

        return f"{protocol}://{target}:{port}"
