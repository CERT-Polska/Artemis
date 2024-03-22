from typing import Annotated, Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonState

from artemis.config import Config
from artemis.db import DB, ColumnOrdering, TaskFilter
from artemis.modules.classifier import Classifier
from artemis.producer import create_tasks
from artemis.templating import render_analyses_table_row, render_task_table_row

router = APIRouter()
db = DB()


def verify_api_token(x_api_token: Annotated[str, Header()]) -> None:
    if not Config.Miscellaneous.API_TOKEN:
        raise HTTPException(
            status_code=401,
            detail="Please provide the API token in the API_TOKEN variable in .env in order to use the API",
        )
    elif x_api_token != Config.Miscellaneous.API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid API token")


@router.post("/add", dependencies=[Depends(verify_api_token)])
def add(
    targets: List[str],
    tag: Annotated[Optional[str], Body()] = None,
    disabled_modules: List[str] = Config.Miscellaneous.MODULES_DISABLED_BY_DEFAULT,
) -> Dict[str, Any]:
    """Add targets to be scanned."""
    for task in targets:
        if not Classifier.is_supported(task):
            return {"error": f"Invalid task: {task}"}

    create_tasks(targets, tag, disabled_modules=disabled_modules)

    return {"ok": True}


@router.get("/analyses", dependencies=[Depends(verify_api_token)])
def list_analysis() -> List[Dict[str, Any]]:
    """Returns the list of analysed targets. Any target you added to scan would be listed here."""
    return db.list_analysis()


@router.get("/num-queued-tasks", dependencies=[Depends(verify_api_token)])
def num_queued_tasks(karton_names: Optional[List[str]] = None) -> int:
    """Return the number of queued tasks for all or only some kartons."""
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


@router.get("/task-results", dependencies=[Depends(verify_api_token)])
def get_task_results(
    only_interesting: bool = False,
    page: int = 1,
    page_size: int = 100,
    analysis_id: Optional[str] = None,
    search: Optional[str] = None,
) -> List[Dict[str, Any]]:
    return db.get_paginated_task_results(
        start=(page - 1) * page_size,
        length=page_size,
        ordering=[ColumnOrdering(column_name="created_at", ascending=True)],
        search_query=search,
        analysis_id=analysis_id,
        task_filter=TaskFilter.INTERESTING if only_interesting else None,
    ).data


@router.get("/analyses-table", include_in_schema=False)
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


@router.get("/task-results-table", include_in_schema=False)
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

    if analysis_id:
        if not db.get_analysis_by_id(analysis_id):
            raise HTTPException(status_code=404, detail="Analysis not found")
        result = db.get_paginated_task_results(
            start,
            length,
            ordering,
            search_query=search_query,
            analysis_id=analysis_id,
            task_filter=task_filter,
        )
    else:
        result = db.get_paginated_task_results(
            start, length, ordering, search_query=search_query, task_filter=task_filter
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
