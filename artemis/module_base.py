import traceback
from abc import abstractmethod
from typing import Any, List, Optional, cast

from karton.core import Karton, Task

from artemis.binds import TaskStatus
from artemis.config import Config
from artemis.db import DB
from artemis.redis_cache import RedisCache
from artemis.resource_lock import ResourceLock


class ArtemisBase(Karton):
    """
    Artemis base module. Provides helpers (such as e.g. cache) for all modules.
    """

    def __init__(self, db: Optional[DB] = None, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args, **kwargs)
        self.cache = RedisCache(Config.REDIS, self.identity)
        self.lock = ResourceLock(redis=Config.REDIS, res_name=self.identity)
        if db:
            self.db = db
        else:
            self.db = DB()

    def add_task(self, current_task: Task, new_task: Task) -> None:
        new_task.root_uid = current_task.root_uid
        if self.db.save_scheduled_task(new_task):
            self.send_task(new_task)


class ArtemisSingleTaskBase(ArtemisBase):
    @abstractmethod
    def run(self, current_task: Task) -> None:
        raise NotImplementedError()

    def process(self, *args: List[Any]) -> None:
        current_task = cast(Task, args[0])
        try:
            self.run(current_task)
        except Exception:
            self.db.save_task_result(task=current_task, status=TaskStatus.ERROR, data=traceback.format_exc())
            raise
