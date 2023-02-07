from karton.core import Producer
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonState
from karton.core.task import TaskState


def restart_crashed_tasks() -> None:
    backend = KartonBackend(config=KartonConfig())
    state = KartonState(backend=backend)

    for queue in state.queues.values():
        identity = "artemis.retry"
        producer = Producer(identity=identity)

        for task in queue.crashed_tasks:
            # spawn a new task and mark the original one as finished
            producer.send_task(task.fork_task())
            backend.set_task_status(task=task, status=TaskState.FINISHED)
