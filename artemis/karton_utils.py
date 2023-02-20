from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonState
from karton.core.task import TaskState


def restart_crashed_tasks() -> None:
    backend = KartonBackend(config=KartonConfig())
    state = KartonState(backend=backend)

    for queue in state.queues.values():
        for task in queue.crashed_tasks:
            # spawn a new task and mark the original one as finished
            new_task = task.fork_task()
            new_task.status = TaskState.SPAWNED
            backend.register_task(new_task)
            backend.produce_routed_task(task.headers["receiver"], new_task)
            backend.set_task_status(task=task, status=TaskState.FINISHED)
