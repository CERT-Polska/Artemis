from typing import Dict, List

from karton.core.backend import KartonBackend, KartonBind
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonState
from karton.core.task import TaskState

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


def get_num_pending_tasks(karton_backend: KartonBackend) -> Dict[str, int]:
    result: Dict[str, int] = {}
    for task in karton_backend.iter_all_tasks():
        if task.status in [TaskState.STARTED, TaskState.SPAWNED, TaskState.DECLARED]:
            result[task.root_uid] = result.get(task.root_uid, 0) + 1
        else:
            assert task.status in [TaskState.FINISHED, TaskState.CRASHED], "Unknown task status: " + str(task.status)
    return result
