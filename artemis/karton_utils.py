from typing import Dict, List

from karton.core.backend import KartonBackend, KartonBind
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonAnalysis, KartonState
from karton.core.task import Task, TaskState, TaskPriority

BINDS_THAT_CANNOT_BE_DISABLED = ["classifier", "webapp_identifier", "IPLookup"]


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


def change_priority_for_analyses(analyses_ids: list[str], new_priority: str, push_to_queue_end: bool = True) -> None:
    backend = KartonBackend(config=KartonConfig())
    state = KartonState(backend=backend)
    analyses = state.analyses
    
    found_analyses = []
    not_found_ids = []
    
    for analysis_id in analyses_ids:
        state_analysis = analyses.get(analysis_id)
        if state_analysis is None:
            not_found_ids.append(analysis_id)
        else:
            found_analyses.append(state_analysis)
    
    if not_found_ids:
        return
    
    tasks = []
    for analysis in found_analyses:
        tasks = analysis.tasks
        
    for task in tasks:
        change_priority_for_task(state, task, new_priority, push_to_queue_end)


def change_priority_for_task(karton_state: KartonState, karton_task: Task, new_priority: str, push_to_queue_end: bool = True) -> None:
    # no need to change priority for running or finished task
    backend = karton_state.backend
    if karton_task.status in [TaskState.STARTED, TaskState.FINISHED, TaskState.CRASHED]:
        return
    
    pipe = backend.redis.pipeline(transaction=True)
    old_priority = karton_task.priority
    if old_priority != new_priority:
        karton_task.priority = TaskPriority(new_priority)
        backend.register_task(karton_task)
    
    if karton_task.status == TaskState.SPAWNED:
        receiver = karton_task.headers.get("receiver")
        if not receiver:
            return
        
        old_queue = backend.get_queue_name(receiver, TaskPriority(old_priority))
        new_queue = backend.get_queue_name(receiver, TaskPriority(new_priority))
        
        pipe.lrem(old_queue, 1, karton_task.uid)
        if push_to_queue_end:
            pipe.rpush(new_queue, karton_task.uid)
        else:
            pipe.lpush(new_queue, karton_task.uid)
    
    pipe.execute()

    