from typing import List, Dict, Any, Optional

from karton.core import Consumer, Task
from karton.core.config import Config as KartonConfig

from artemis.db import DB
from artemis.module_base import ArtemisBase


class CleanupTask(ArtemisBase):
    old_modules = ["dalfox"]

    def __init__(self, db: Optional[DB] = None, *args, **kwargs):
        super().__init__(db, *args, **kwargs)

        for old_module in self.old_modules:
            class KartonDummy(Consumer):
                identity = old_module
                persistent = False
                filters: List[Dict[str, Any]] = []

                def process(self, task: Task) -> None:
                    pass

            karton = KartonDummy(config=KartonConfig())
            karton._shutdown = True
            karton.loop()


if __name__ == "__main__":
    CleanupTask().loop()
