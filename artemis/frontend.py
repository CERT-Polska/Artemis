import json
import urllib
from os import getenv
from typing import List, Optional

from fastapi import APIRouter, File, Form, Header, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonState

from artemis.db import DB, TaskFilter
from artemis.json_utils import JSONEncoderWithDataclasses
from artemis.karton_utils import restart_crashed_tasks
from artemis.producer import create_tasks
from artemis.templating import templates

router = APIRouter()
db = DB()


@router.get("/", include_in_schema=False)
def get_root(request: Request) -> Response:
    karton_state = KartonState(backend=KartonBackend(config=KartonConfig()))

    entries = []
    for entry in db.list_analysis():
        if entry["_id"] in karton_state.analyses:
            num_active_tasks = len(karton_state.analyses[entry["_id"]].pending_tasks)
        else:
            num_active_tasks = 0

        entries.append(
            {
                "payload": entry["payload"],
                "id": entry["_id"],
                "num_active_tasks": num_active_tasks,
            }
        )

    return templates.TemplateResponse(
        "index.jinja2",
        {"request": request, "entries": entries},
    )


@router.get("/add", include_in_schema=False)
def get_add_form(request: Request) -> Response:
    return templates.TemplateResponse("add.jinja2", {"request": request})


@router.post("/add", include_in_schema=False)
def post_add(
    targets: Optional[str] = Form(None),
    file: Optional[bytes] = File(None),
) -> Response:
    total_list: List[str] = []
    if targets:
        total_list += (x.strip() for x in targets.split())
    if file:
        total_list += (x.strip() for x in file.decode().split())
    create_tasks(total_list)
    return RedirectResponse("/", status_code=301)


@router.get("/restart-crashed-tasks")
def get_restart_crashed_tasks(request: Request) -> Response:
    return templates.TemplateResponse(
        "/restart_crashed_tasks.jinja2",
        {
            "request": request,
        },
    )


@router.post("/restart-crashed-tasks")
def post_restart_crashed_tasks(request: Request) -> Response:
    restart_crashed_tasks()
    return RedirectResponse("/", status_code=301)


@router.get("/queue", include_in_schema=False)
def get_queue(request: Request) -> Response:
    return templates.TemplateResponse(
        "queue.jinja2",
        {
            "request": request,
            "dashboard_url": getenv("DASHBOARD_URL", "http://localhost:5001"),
        },
    )


@router.get("/analysis/{root_id}", include_in_schema=False)
def get_analysis(
    request: Request, root_id: str, task_filter: Optional[TaskFilter] = None
) -> Response:
    analysis = db.get_analysis_by_id(root_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    api_url_parameters = {"analysis_id": analysis["root_uid"]}

    if task_filter:
        api_url_parameters["task_filter"] = task_filter.value

    return templates.TemplateResponse(
        "task_list.jinja2",
        {
            "request": request,
            "title": f"Analysis of { analysis['payload']['data'] }",
            "api_url": "/api/task-results?"
            + urllib.parse.urlencode(api_url_parameters),
            "task_filter": task_filter,
        },
    )


@router.get("/results", include_in_schema=False)
def get_results(request: Request, task_filter: Optional[TaskFilter] = None) -> Response:
    if task_filter:
        api_url_parameters = {"task_filter": task_filter.value}
    else:
        api_url_parameters = {}
    return templates.TemplateResponse(
        "task_list.jinja2",
        {
            "request": request,
            "title": "Results",
            "api_url": "/api/task-results?"
            + urllib.parse.urlencode(api_url_parameters),
            "task_filter": task_filter,
        },
    )


@router.get("/task/{task_id}", include_in_schema=False)
def get_task(
    task_id: str, request: Request, referer: str = Header(default="/")
) -> Response:
    task = db.get_task_by_id(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return templates.TemplateResponse(
        "task.jinja2",
        {
            "request": request,
            "task": task,
            "referer": referer,
            "pretty_printed": json.dumps(
                task, indent=4, cls=JSONEncoderWithDataclasses
            ),
        },
    )
