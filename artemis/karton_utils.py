from typing import List

from karton.core.backend import KartonBackend, KartonBind
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonState

BINDS_THAT_CANNOT_BE_DISABLED = ["classifier", "http_service_to_url", "webapp_identifier", "IPLookup"]


def get_binds_that_can_be_disabled() -> List[KartonBind]:
    backend = KartonBackend(config=KartonConfig())

    binds = []
    for bind in backend.get_binds():
        if bind.identity in BINDS_THAT_CANNOT_BE_DISABLED:
            # Not allowing to disable as it's a core module
            continue

        binds.append(bind)

    return binds


def restart_crashed_tasks() -> None:
    backend = KartonBackend(config=KartonConfig())
    state = KartonState(backend=backend)

    for queue in state.queues.values():
        for task in queue.crashed_tasks:
            backend.restart_task(task)
