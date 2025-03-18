import datetime
from typing import Annotated, Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonState
from karton.core.task import TaskPriority
from pydantic import BaseModel
from redis import Redis

from artemis.config import Config
from artemis.db import DB, ColumnOrdering, TaskFilter
from artemis.karton_utils import get_binds_that_can_be_disabled
from artemis.modules.classifier import Classifier
from artemis.producer import create_tasks
from artemis.reporting.base.language import Language
from artemis.task_utils import (
    get_analysis_num_finished_tasks,
    get_analysis_num_in_progress_tasks,
)
from artemis.templating import render_analyses_table_row, render_task_table_row

router = APIRouter()
db = DB()
redis = Redis.from_url(Config.Data.REDIS_CONN_STR)


class ReportGenerationTaskModel(BaseModel):
    id: int
    created_at: datetime.datetime
    comment: Optional[str]
    tag: Optional[str]
    status: str
    language: str
    skip_previously_exported: bool
    zip_url: Optional[str]
    error: Optional[str]
    alerts: Any


def verify_api_token(x_api_token: Annotated[str, Header()]) -> None:
    if not Config.Miscellaneous.API_TOKEN:
        raise HTTPException(
            status_code=401,
            detail="Please fill the API_TOKEN variable in .env in order to use the API",
        )
    elif x_api_token != Config.Miscellaneous.API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid API token")


@router.post("/add", dependencies=[Depends(verify_api_token)])
def add(
    targets: List[str],
    tag: str | None = Body(default=None),
    disabled_modules: Optional[List[str]] = Body(default=None),
    enabled_modules: Optional[List[str]] = Body(default=None),
    requests_per_second_override: Optional[float] = Body(default=None),
    priority: str = Body(default="normal"),
) -> Dict[str, Any]:
    """Add targets to be scanned."""
    if disabled_modules and enabled_modules:
        raise HTTPException(
            status_code=400, detail="It's not possible to set both disabled_modules and enabled_modules."
        )

    for task in targets:
        if not Classifier.is_supported(task):
            return {"error": f"Invalid task: {task}"}

    identities_that_can_be_disabled = set([bind.identity for bind in get_binds_that_can_be_disabled()])

    if enabled_modules:
        if len(set(enabled_modules) - identities_that_can_be_disabled) > 0:
            raise HTTPException(
                status_code=400,
                detail=f"The following modules from enabled_modules either don't exist or must always be enabled: {','.join(set(enabled_modules) - identities_that_can_be_disabled)}",
            )

    if enabled_modules:
        # Let's disable all modules that can be disabled and aren't included in enabled_modules
        disabled_modules = list(identities_that_can_be_disabled - set(enabled_modules))
    elif not disabled_modules:
        disabled_modules = Config.Miscellaneous.MODULES_DISABLED_BY_DEFAULT

    create_tasks(
        targets,
        tag,
        disabled_modules=disabled_modules,
        priority=TaskPriority(priority),
        requests_per_second_override=requests_per_second_override,
    )

    return {"ok": True}


@router.get("/analyses", dependencies=[Depends(verify_api_token)])
def list_analysis() -> List[Dict[str, Any]]:
    """Returns the list of analysed targets. Any scanned target would be listed here."""
    analyses = db.list_analysis()
    karton_state = KartonState(backend=KartonBackend(config=KartonConfig()))
    for analysis in analyses:
        analysis["num_pending_tasks"] = (
            len(karton_state.analyses[analysis["id"]].pending_tasks) if analysis["id"] in karton_state.analyses else 0
        )
    return analyses


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
    only_interesting: bool = True,
    page: int = 1,
    page_size: int = 100,
    analysis_id: Optional[str] = None,
    search: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return raw results of the scanning tasks."""
    return db.get_paginated_task_results(
        start=(page - 1) * page_size,
        length=page_size,
        ordering=[ColumnOrdering(column_name="created_at", ascending=True)],
        search_query=search,
        analysis_id=analysis_id,
        task_filter=TaskFilter.INTERESTING if only_interesting else None,
    ).data


@router.post("/stop-and-delete-analysis", dependencies=[Depends(verify_api_token)])
def stop_and_delete_analysis(analysis_id: str) -> Dict[str, bool]:
    backend = KartonBackend(config=KartonConfig())

    for task in backend.get_all_tasks():
        if task.root_uid == analysis_id:
            backend.delete_task(task)

    if db.get_analysis_by_id(analysis_id):
        db.delete_analysis(analysis_id)

    return {"ok": True}


@router.post("/archive-tag", dependencies=[Depends(verify_api_token)])
def archive_tag(tag: str) -> Dict[str, bool]:
    db.create_tag_archive_request(tag)
    return {"ok": True}


@router.get("/exports", dependencies=[Depends(verify_api_token)])
def get_exports(tag_prefix: Optional[str] = None) -> List[ReportGenerationTaskModel]:
    """List all exports. An export is a request to create human-readable messages that may be sent to scanned entities."""
    return [
        ReportGenerationTaskModel(
            id=task.id,
            created_at=task.created_at,
            comment=task.comment,
            tag=task.tag,
            status=task.status,
            language=task.language,
            skip_previously_exported=task.skip_previously_exported,
            zip_url=f"/api/export/download-zip/{task.id}" if task.output_location else None,
            error=task.error,
            alerts=task.alerts,
        )
        for task in db.list_report_generation_tasks(tag_prefix=tag_prefix)
    ]


# This is a redirect so that we have an entry in api docs
@router.get("/export/download-zip/{id}", dependencies=[Depends(verify_api_token)])
def download_zip(id: int) -> RedirectResponse:
    """Download a zip file containing an export - all messages that can be sent to scanned entities + additional data such as statistics."""
    return RedirectResponse(f"/export/download-zip/{id}")


@router.post("/export/delete/{id}", dependencies=[Depends(verify_api_token)])
async def post_export_delete(id: int) -> Dict[str, Any]:
    """Delete an export."""
    db.delete_report_generation_task(id)
    return {
        "ok": True,
    }


@router.post("/export", dependencies=[Depends(verify_api_token)])
async def post_export(
    language: str = Body(),
    skip_previously_exported: bool = Body(),
    tag: Optional[str] = Body(None),
    comment: Optional[str] = Body(None),
    custom_template_arguments: Dict[str, Any] = Body({}),
    skip_hooks: bool = Body(False),
    skip_suspicious_reports: bool = Body(False),
) -> Dict[str, Any]:
    """Create a new export. An export is a request to create human-readable messages that may be sent to scanned entities."""
    db.create_report_generation_task(
        skip_previously_exported=skip_previously_exported,
        tag=tag,
        comment=comment,
        custom_template_arguments=custom_template_arguments,
        language=Language(language),
        skip_hooks=skip_hooks,
        skip_suspicious_reports=skip_suspicious_reports,
    )
    return {
        "ok": True,
    }


@router.get("/analyses-table", include_in_schema=False)
def get_analyses_table(
    request: Request,
    draw: int = Query(),
    start: int = Query(),
    length: int = Query(),
) -> Dict[str, Any]:
    ordering = _get_ordering(request, column_names=["created_at", "target", "tag", None, None])
    search_query = _get_search_query(request)

    karton_state = KartonState(backend=KartonBackend(config=KartonConfig()))

    result = db.get_paginated_analyses(start, length, ordering, search_query=search_query)

    entries = []
    for entry in result.data:
        if entry["id"] in karton_state.analyses:
            num_pending_tasks = len(karton_state.analyses[entry["id"]].pending_tasks)
        else:
            num_pending_tasks = 0

        num_finished_tasks = get_analysis_num_finished_tasks(redis, entry["id"])
        num_in_progress_tasks = get_analysis_num_in_progress_tasks(redis, entry["id"])
        num_all_tasks = num_finished_tasks + num_in_progress_tasks + num_pending_tasks

        entries.append(
            {
                "id": entry["id"],
                "tag": entry["tag"],
                "target": entry["target"],
                "created_at": entry["created_at"],
                "disabled_modules": entry["disabled_modules"],
                "num_pending_tasks": num_pending_tasks,
                "num_all_tasks": num_all_tasks,
                "num_finished_tasks": num_finished_tasks,
                "percentage_finished_tasks": 100.0 * num_finished_tasks / num_all_tasks if num_all_tasks else "N/A",
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
