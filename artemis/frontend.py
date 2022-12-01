import json
from os import getenv, path
from typing import List, Optional

from fastapi import APIRouter, File, Form, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonState

from artemis.db import DB
from artemis.producer import create_tasks

templates_dir = path.join(path.dirname(__file__), "..", "templates")
templates = Jinja2Templates(directory=templates_dir)
router = APIRouter()
db = DB()


@router.get("/", include_in_schema=False)
def get_root(request: Request) -> Response:
    karton_state = KartonState(backend=KartonBackend(config=KartonConfig()))  # type: ignore[no-untyped-call]

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
    urls: Optional[str] = Form(None),
    file: Optional[bytes] = File(None),
) -> Response:
    total_list: List[str] = []
    if urls:
        total_list += (x.strip() for x in urls.split())
    if file:
        total_list += (x.strip() for x in file.decode().split())
    create_tasks(total_list)
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
def get_analysis(request: Request, root_id: str, status: Optional[str] = None) -> Response:
    analysis = db.get_analysis_by_id(root_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    return templates.TemplateResponse(
        "analysis.jinja2",
        {
            "request": request,
            "status": status,
            "analysis": analysis,
            "pretty_printed": json.dumps(analysis, indent=4),
        },
    )


@router.get("/task/{task_id}", include_in_schema=False)
def get_task(task_id: str, request: Request) -> Response:
    task = db.get_task_by_id(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return templates.TemplateResponse(
        "task.jinja2",
        {
            "request": request,
            "task": task,
            "pretty_printed": json.dumps(task, indent=4),
        },
    )
