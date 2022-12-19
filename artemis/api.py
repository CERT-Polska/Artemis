from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException, Request

from artemis.db import DB, TaskFilter
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
    draw: int,
    start: int,
    length: int,
    analysis_id: Optional[str] = None,
    task_filter: Optional[TaskFilter] = None,
) -> Dict[str, Any]:
    ordering = _build_ordering_from_datatables_column_ids(request)

    if analysis_id:
        if not db.get_analysis_by_id(analysis_id):
            raise HTTPException(status_code=404, detail="Analysis not found")
        result = db.get_paginated_task_results(
            start, length, ordering, analysis_id=analysis_id, task_filter=task_filter
        )
    else:
        result = db.get_paginated_task_results(start, length, ordering, task_filter=task_filter)

    return {
        "draw": draw,
        "recordsTotal": result.records_count_total,
        "recordsFiltered": result.records_count_filtered,
        "data": [render_table_row(task) for task in result.data],
    }


def _build_ordering_from_datatables_column_ids(request: Request) -> List[Tuple[str, str]]:
    column_names = ["created_at", "headers.receiver", "target_str", None, "status_reason", "decision_type"]
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
            ordering.append((column_name, request.query_params[dir_key]))
        i += 1
    return ordering
