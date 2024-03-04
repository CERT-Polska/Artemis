from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonState

from artemis.db import DB, ColumnOrdering, TaskFilter
from artemis.templating import render_analyses_table_row, render_task_table_row

router = APIRouter()
db = DB()


@router.get("/task/{task_id}")
def get_task(task_id: str) -> Dict[str, Any]:
    if result := db.get_task_by_id(task_id):
        return result
    raise HTTPException(status_code=404, detail="Task not found")


@router.get("/analysis")
def list_analysis() -> List[Dict[str, Any]]:
    return db.list_analysis()


@router.get("/num-queued-tasks")
def num_queued_tasks(karton_names: Optional[List[str]] = Query(default=None)) -> int:
    # We check the backend redis queue length directly to avoid the long runtimes of
    # KartonState.get_all_tasks()
    backend = KartonBackend(config=KartonConfig())

    if karton_names:
        sum_all = 0
        for karton_name in karton_names:
            sum_all += sum([backend.redis.llen(key) for key in backend.redis.keys(f"karton.queue.*:{karton_name}")])
        return sum_all
    else:
        return sum([backend.redis.llen(key) for key in backend.redis.keys("karton.queue.*")])


@router.get("/analysis/{root_id}")
def get_analysis(root_id: str) -> Dict[str, Any]:
    if result := db.get_analysis_by_id(root_id):
        return result
    raise HTTPException(status_code=404, detail="Analysis not found")


@router.get("/analyses-table")
def get_analyses_table(
    request: Request,
    draw: int = Query(),
    start: int = Query(),
    length: int = Query(),
) -> Dict[str, Any]:
    ordering = _get_ordering(request, column_names=["target", "tag", None, None])
    search_query = _get_search_query(request)

    karton_state = KartonState(backend=KartonBackend(config=KartonConfig()))

    result = db.get_paginated_analyses(start, length, ordering, search_query=search_query)

    entries = []
    for entry in result.data:
        if entry["id"] in karton_state.analyses:
            num_active_tasks = len(karton_state.analyses[entry["id"]].pending_tasks)
        else:
            num_active_tasks = 0

        entries.append(
            {
                "id": entry["id"],
                "tag": entry["tag"],
                "payload": entry["task"]["payload"],
                "payload_persistent": entry["task"]["payload_persistent"],
                "num_active_tasks": num_active_tasks,
                "stopped": entry.get("stopped", None),
            }
        )

    return {
        "draw": draw,
        "recordsTotal": result.records_count_total,
        "recordsFiltered": result.records_count_filtered,
        "data": [render_analyses_table_row(entry) for entry in entries],
    }


@router.get("/task-results-table")
def get_task_results_table(
    request: Request,
    analysis_id: Optional[str] = Query(default=None),
    task_filter: Optional[TaskFilter] = Query(default=None),
    draw: int = Query(),
    start: int = Query(),
    length: int = Query(),
) -> Dict[str, Any]:
    ordering = _get_ordering(
        request,
        column_names=["created_at", "tag", "receiver", "target_string", None, "status_reason"],
    )
    search_query = _get_search_query(request)

    fields = [
        "created_at",
        "target_string",
        "headers",
        "payload_persistent",
        "status",
        "status_reason",
        "priority",
        "uid",
        "decision_type",
        "operator_comment",
    ]

    if analysis_id:
        if not db.get_analysis_by_id(analysis_id):
            raise HTTPException(status_code=404, detail="Analysis not found")
        result = db.get_paginated_task_results(
            start,
            length,
            ordering,
            fields=fields,
            search_query=search_query,
            analysis_id=analysis_id,
            task_filter=task_filter,
        )
    else:
        result = db.get_paginated_task_results(
            start, length, ordering, fields=fields, search_query=search_query, task_filter=task_filter
        )

    return {
        "draw": draw,
        "recordsTotal": result.records_count_total,
        "recordsFiltered": result.records_count_filtered,
        "data": [render_task_table_row(task) for task in result.data],
    }


def _get_ordering(request: Request, column_names: List[Optional[str]]) -> List[ColumnOrdering]:
    ordering = []

    # Unfortunately, I was not able to find a less ugly way of extracting order[0][column]
    # parameters from FastAPI query string. Feel free to refactor these lines.
    i = 0
    while True:
        column_key = f"order[{i}][column]"
        dir_key = f"order[{i}][dir]"
        if column_key not in request.query_params or dir_key not in request.query_params:
            break
        column_name = column_names[int(request.query_params[column_key])]
        if column_name:
            ordering.append(ColumnOrdering(column_name=column_name, ascending=request.query_params[dir_key] == "asc"))
        i += 1
    return ordering


def _get_search_query(request: Request) -> Optional[str]:
    i = 0
    while True:
        search_value_key = f"columns[{i}][search][value]"
        search_regex_key = f"columns[{i}][search][regex]"
        if search_value_key not in request.query_params:
            break
        if request.query_params[search_value_key].strip() != "":
            raise NotImplementedError("Per-column search is not yet implemented")
        if request.query_params[search_regex_key] != "false":
            raise NotImplementedError("Regex search is not yet implemented")
        i += 1

    if request.query_params["search[regex]"] != "false":
        raise NotImplementedError("Regex search is not yet implemented")

    return request.query_params["search[value]"]
