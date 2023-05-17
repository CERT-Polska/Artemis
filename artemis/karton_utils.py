from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonState


def restart_crashed_tasks() -> None:
    backend = KartonBackend(config=KartonConfig())
    state = KartonState(backend=backend)

    for queue in state.queues.values():
        for task in queue.crashed_tasks:
            backend.restart_task(task)
