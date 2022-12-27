from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request

from artemis.db import DB, ColumnOrdering, TaskFilter
from artemis.templating import render_table_row

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


@router.get("/analysis/{root_id}")
def get_analysis(root_id: str) -> Dict[str, Any]:
    if result := db.get_analysis_by_id(root_id):
        return result
    raise HTTPException(status_code=404, detail="Analysis not found")


@router.get("/task-results")
def get_task_results(
    request: Request,
    analysis_id: Optional[str] = Query(default=None),
    task_filter: Optional[TaskFilter] = Query(default=None),
    draw: int = Query(),
    start: int = Query(),
    length: int = Query(),
) -> Dict[str, Any]:
    ordering = _get_ordering(request)

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

    search_query = request.query_params["search[value]"]

    if analysis_id:
        if not db.get_analysis_by_id(analysis_id):
            raise HTTPException(status_code=404, detail="Analysis not found")
        result = db.get_paginated_task_results(
            start, length, ordering, search_query=search_query, analysis_id=analysis_id, task_filter=task_filter
        )
    else:
        result = db.get_paginated_task_results(
            start, length, ordering, search_query=search_query, task_filter=task_filter
        )

    return {
        "draw": draw,
        "recordsTotal": result.records_count_total,
        "recordsFiltered": result.records_count_filtered,
        "data": [render_table_row(task) for task in result.data],
    }


def _get_ordering(request: Request) -> List[ColumnOrdering]:
    column_names = ["created_at", "headers.receiver", "target_string", None, "status_reason", "decision_type"]
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
