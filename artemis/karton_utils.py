from karton.core import Task
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonState
from requests.exceptions import RequestException

from artemis.binds import TaskStatus
from artemis.db import DB
from artemis.http_requests import get
from artemis.task_utils import get_target_url


def restart_crashed_tasks() -> None:
    backend = KartonBackend(config=KartonConfig())
    state = KartonState(backend=backend)

    for queue in state.queues.values():
        for task in queue.crashed_tasks:
            backend.restart_task(task)


def check_connection_to_base_url_and_save_error(db: DB, task: Task) -> bool:
    base_url = get_target_url(task)
    try:
        get(base_url)
        return True
    except RequestException:
        db.save_task_result(
            task=task,
            status=TaskStatus.ERROR,
            status_reason=f"Unable to connect to base URL: {base_url}, task skipped",
        )
        return False
