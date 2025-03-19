import glob
import json
import os
import urllib
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional
from zipfile import ZipFile

import requests
from fastapi import APIRouter, Depends, Form, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi_csrf_protect import CsrfProtect
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from karton.core.inspect import KartonState
from karton.core.task import TaskPriority, TaskState
from starlette.datastructures import Headers

from artemis import csrf
from artemis.binds import TaskType
from artemis.config import Config
from artemis.db import DB, ColumnOrdering, ReportGenerationTaskStatus, TaskFilter
from artemis.json_utils import JSONEncoderAdditionalTypes
from artemis.karton_utils import get_binds_that_can_be_disabled, restart_crashed_tasks
from artemis.modules.classifier import Classifier
from artemis.producer import create_tasks
from artemis.reporting.base.language import Language
from artemis.task_utils import get_task_target
from artemis.templating import templates

router = APIRouter()
db = DB()


def whitelist_proxy_request_headers(headers: Headers) -> Dict[str, str]:
    result = {}
    for header in headers:
        if header.lower() in ["referer", "referrer"]:
            result[header] = headers[header]
    return result


def whitelist_proxy_response_headers(headers: requests.structures.CaseInsensitiveDict[str]) -> Dict[str, str]:
    result = {}
    for header in headers:
        if header.lower() in [
            "content-type",
            "content-length",
            "last-modified",
            "cache-control",
            "etag",
            "content-encoding",
            "location",
        ]:
            result[header] = headers[header]
    return result


def error_content_not_found(request: Request, exc: HTTPException) -> Response:
    if request.url.path.startswith("/api"):
        return JSONResponse({"error": 404}, status_code=404)
    else:
        return templates.TemplateResponse("not_found.jinja2", {"request": request}, status_code=404)


if not Config.Miscellaneous.API_TOKEN:

    @router.get("/docs", include_in_schema=False)
    def api_docs_information(request: Request) -> Response:
        return templates.TemplateResponse(
            "no_api_token.jinja2",
            {
                "request": request,
            },
        )


@router.get("/", include_in_schema=False)
def get_root(request: Request) -> Response:
    karton_state = KartonState(backend=KartonBackend(config=KartonConfig()))
    has_analyses = len(list(db.get_paginated_analyses(0, 1, [ColumnOrdering("target", True)]).data)) > 0
    has_finished_analyses = False

    for analysis in db.list_analysis():
        if analysis["id"] not in karton_state.analyses or len(karton_state.analyses[analysis["id"]].pending_tasks) == 0:
            has_finished_analyses = True

    return templates.TemplateResponse(
        "index.jinja2",
        {
            "request": request,
            "has_analyses": has_analyses,
            "has_finished_analyses": has_finished_analyses,
            "api_url": "/api/analyses-table",
            "num_active_tasks": sum([len(analysis.pending_tasks) for analysis in karton_state.analyses.values()]),
        },
    )


@router.get("/add", include_in_schema=False)
def get_add_form(request: Request, csrf_protect: CsrfProtect = Depends()) -> Response:
    binds = sorted(get_binds_that_can_be_disabled(), key=lambda bind: bind.identity.lower())

    return csrf.csrf_form_template_response(
        "add.jinja2",
        {
            "request": request,
            "binds": binds,
            "priority": TaskPriority.NORMAL.value,
            "priorities": list(TaskPriority),
            "modules_disabled_by_default": Config.Miscellaneous.MODULES_DISABLED_BY_DEFAULT,
        },
        csrf_protect,
    )


@router.post("/add", include_in_schema=False)
@csrf.validate_csrf
async def post_add(
    request: Request,
    targets: str = Form(),
    tag: Optional[str] = Form(None),
    priority: Optional[str] = Form(None),
    choose_modules_to_enable: Optional[bool] = Form(None),
    redirect: bool = Form(True),
    csrf_protect: CsrfProtect = Depends(),
) -> Response:
    disabled_modules = []

    if choose_modules_to_enable:
        async with request.form() as form:
            for bind in get_binds_that_can_be_disabled():
                if f"module_enabled_{bind.identity}" not in form:
                    disabled_modules.append(bind.identity)

    total_list: List[str] = []
    if targets:
        targets = targets.strip()
        total_list += (x.strip() for x in targets.split("\n"))

    validation_messages = []
    for task in total_list:
        if not Classifier.is_supported(task):
            validation_messages.append(
                f"{task} is not supported - Artemis supports domains, IPs or IPv4 ranges. Domains and IPs may also optionally be followed by port number."
            )

    for dependency, task_types in [
        ("port_scanner", [TaskType.SERVICE.value, TaskType.WEBAPP.value]),
        ("device_identifier", [TaskType.DEVICE.value]),
    ]:
        if dependency in disabled_modules:
            for bind in get_binds_that_can_be_disabled():
                if bind.identity not in disabled_modules:
                    for item in bind.filters:
                        if "type" in item and item["type"] in task_types:
                            validation_messages.append(f"Module {bind.identity} requires {dependency} to be enabled")

    if validation_messages:
        binds = sorted(get_binds_that_can_be_disabled(), key=lambda bind: bind.identity.lower())
        return csrf.csrf_form_template_response(
            "add.jinja2",
            {
                "validation_message": ", ".join(validation_messages),
                "request": request,
                "binds": binds,
                "priority": priority,
                "priorities": list(TaskPriority),
                "tasks": total_list,
                "tag": tag or "",
                "disabled_modules": disabled_modules,
                "modules_disabled_by_default": Config.Miscellaneous.MODULES_DISABLED_BY_DEFAULT,
            },
            csrf_protect,
        )

    create_tasks(total_list, tag, disabled_modules, TaskPriority(priority))
    if redirect:
        return RedirectResponse("/", status_code=301)
    else:
        return Response(
            content="OK",
            status_code=200,
        )


@router.get("/exports", include_in_schema=False)
def get_exports(request: Request) -> Response:
    return templates.TemplateResponse(
        "exports.jinja2",
        {
            "request": request,
            "report_generation_tasks": db.list_report_generation_tasks(),
        },
    )


@router.get("/export", include_in_schema=False)
def get_export_form(request: Request, csrf_protect: CsrfProtect = Depends()) -> Response:
    return csrf.csrf_form_template_response(
        "export.jinja2",
        {
            "request": request,
            "languages": list(Language),
        },
        csrf_protect,
    )


@router.get("/export/delete/{id}", include_in_schema=False)
def export_delete_form(request: Request, id: int, csrf_protect: CsrfProtect = Depends()) -> Response:
    task = db.get_report_generation_task(id)
    return csrf.csrf_form_template_response(
        "export_delete_form.jinja2",
        {
            "request": request,
            "task": task,
        },
        csrf_protect,
    )


@router.get("/export/view/{id}", include_in_schema=False)
def view_export(request: Request, id: int) -> Response:
    task = db.get_report_generation_task(id)

    if not task:
        raise HTTPException(status_code=404, detail="Report generation task not found")

    vulnerabilities = []

    num_high_severity = 0
    num_medium_severity = 0
    num_low_severity = 0

    if task.status == "done":
        domain_messages = {}
        messages_path = os.path.join(task.output_location, "messages")
        for item in os.listdir(messages_path):
            with open(os.path.join(messages_path, item)) as f:
                domain_messages[item.removesuffix(".html")] = f.read()

        with open(os.path.join(task.output_location, "advanced", "output.json")) as f:
            data = json.load(f)

            for message in data["messages"].values():
                for report in message["reports"]:
                    vulnerabilities.append(report)
                    if report["severity"] == "high":
                        num_high_severity += 1
                    elif report["severity"] == "medium":
                        num_medium_severity += 1
                    elif report["severity"] == "low":
                        num_low_severity += 1
                    else:
                        assert False

    else:
        domain_messages = {}

    return templates.TemplateResponse(
        "view_export.jinja2",
        {
            "domain_messages": domain_messages,
            "request": request,
            "num_high_severity": num_high_severity,
            "num_medium_severity": num_medium_severity,
            "num_low_severity": num_low_severity,
            "vulnerabilities": vulnerabilities,
            "task": task,
        },
    )


@router.post("/export/confirm-delete/{id}", include_in_schema=False)
@csrf.validate_csrf
async def post_export_delete(request: Request, id: int, csrf_protect: CsrfProtect = Depends()) -> Response:
    db.delete_report_generation_task(id)
    return RedirectResponse("/exports", status_code=301)


@router.get("/export/download-zip/{id}", include_in_schema=False)
def export_download_zip(request: Request, id: int) -> Response:
    task = db.get_report_generation_task(id)
    if not task:
        raise HTTPException(status_code=404, detail="Report generation task not found")
    if task.status != ReportGenerationTaskStatus.DONE.value:
        raise HTTPException(status_code=404, detail="Report generation task not yet finished")

    byte_stream = BytesIO()
    zipfile = ZipFile(byte_stream, "w")

    for path in glob.glob(str(Path(task.output_location) / "**" / "*"), recursive=True):
        zipfile.write(path, os.path.relpath(path, task.output_location))
    zipfile.close()

    return Response(
        byte_stream.getvalue(), headers={"Content-Disposition": f"attachment; filename=artemis-export-{id}.zip"}
    )


@router.post("/export", include_in_schema=False)
@csrf.validate_csrf
async def post_export(
    request: Request,
    csrf_protect: CsrfProtect = Depends(),
    tag: Optional[str] = Form(None),
    comment: Optional[str] = Form(None),
    language: Optional[str] = Form(None),
    skip_previously_exported: Optional[str] = Form(None),
) -> Response:
    db.create_report_generation_task(
        skip_previously_exported=skip_previously_exported == "yes",
        tag=tag,
        comment=comment,
        language=Language(language),
    )
    return RedirectResponse("/exports", status_code=301)


@router.get("/remove-finished-analyses", include_in_schema=False)
def get_remove_finished_analyses(request: Request, csrf_protect: CsrfProtect = Depends()) -> Response:
    return csrf.csrf_form_template_response(
        "/remove_finished_analyses.jinja2",
        {
            "request": request,
        },
        csrf_protect,
    )


@router.post("/remove-finished-analyses", include_in_schema=False)
@csrf.validate_csrf
async def post_remove_finished_analyses(request: Request, csrf_protect: CsrfProtect = Depends()) -> Response:
    karton_state = KartonState(backend=KartonBackend(config=KartonConfig()))
    for analysis in db.list_analysis():
        if analysis["id"] not in karton_state.analyses or len(karton_state.analyses[analysis["id"]].pending_tasks) == 0:
            db.delete_analysis(analysis["id"])
    return RedirectResponse("/", status_code=301)


@router.get("/analysis/remove-pending-tasks/{analysis_id}", include_in_schema=False)
def get_remove_pending_tasks(request: Request, analysis_id: str, csrf_protect: CsrfProtect = Depends()) -> Response:
    return csrf.csrf_form_template_response(
        "/remove_pending_tasks.jinja2",
        {
            "analysis_id": analysis_id,
            "analysed_object": db.get_analysis_by_id(analysis_id)["target"],  # type: ignore
            "request": request,
        },
        csrf_protect,
    )


@router.post("/analysis/remove-pending-tasks/{analysis_id}", include_in_schema=False)
@csrf.validate_csrf
async def post_remove_pending_tasks(
    request: Request, analysis_id: str, csrf_protect: CsrfProtect = Depends()
) -> Response:
    db.mark_analysis_as_stopped(analysis_id)

    backend = KartonBackend(config=KartonConfig())

    for task in backend.get_all_tasks():
        if task.root_uid == analysis_id:
            backend.delete_task(task)

    return RedirectResponse("/", status_code=301)


@router.get("/analysis/get-pending-tasks/{analysis_id}", include_in_schema=False)
async def get_pending_tasks(request: Request, analysis_id: str) -> Response:
    analysis = db.get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    backend = KartonBackend(config=KartonConfig())

    tasks = []
    for task in backend.get_all_tasks():
        if task.root_uid == analysis_id:
            if task.status in [TaskState.SPAWNED, TaskState.STARTED]:
                tasks.append((task, get_task_target(task)))

    return templates.TemplateResponse(
        "pending_tasks.jinja2",
        {
            "title": analysis["target"],
            "request": request,
            "tasks": tasks,
            "num_tasks": len(tasks),
        },
    )


@router.get("/restart-crashed-tasks", include_in_schema=False)
def get_restart_crashed_tasks(request: Request, csrf_protect: CsrfProtect = Depends()) -> Response:
    return csrf.csrf_form_template_response(
        "/restart_crashed_tasks.jinja2",
        {
            "request": request,
        },
        csrf_protect,
    )


@router.post("/restart-crashed-tasks", include_in_schema=False)
@csrf.validate_csrf
async def post_restart_crashed_tasks(request: Request, csrf_protect: CsrfProtect = Depends()) -> Response:
    restart_crashed_tasks()
    return RedirectResponse("/", status_code=301)


@router.get("/queue", include_in_schema=False)
def get_queue(request: Request) -> Response:
    return templates.TemplateResponse(
        "queue.jinja2",
        {
            "request": request,
        },
    )


@router.api_route("/karton-dashboard/{path:path}", methods=["GET", "POST"], include_in_schema=False)
async def karton_dashboard(request: Request, path: str) -> Response:
    response = requests.request(
        url="http://karton-dashboard:5000/karton-dashboard/" + path,
        method=request.method,
        allow_redirects=False,
        headers={"connection": "close", **whitelist_proxy_request_headers(request.headers)},
    )
    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=whitelist_proxy_response_headers(response.headers),
    )


@router.api_route("/metrics", methods=["GET"], include_in_schema=False)
async def prometheus(request: Request) -> Response:
    response = requests.get(url="http://metrics:9000/")
    return Response(
        content=response.content,
        status_code=response.status_code,
    )


@router.get("/analysis/{root_id}", include_in_schema=False)
def get_analysis(request: Request, root_id: str, task_filter: Optional[TaskFilter] = None) -> Response:
    analysis = db.get_analysis_by_id(root_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    api_url_parameters = {"analysis_id": root_id}

    if task_filter:
        api_url_parameters["task_filter"] = task_filter.value

    return templates.TemplateResponse(
        "task_list.jinja2",
        {
            "request": request,
            "title": f"Analysis of { analysis['target'] }",
            "api_url": "/api/task-results-table?" + urllib.parse.urlencode(api_url_parameters),
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
            "api_url": "/api/task-results-table?" + urllib.parse.urlencode(api_url_parameters),
            "task_filter": task_filter,
        },
    )


@router.get("/task/{task_id}", include_in_schema=False)
def get_task(task_id: str, request: Request, referer: str = Header(default="/")) -> Response:
    task = db.get_task_by_id(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return templates.TemplateResponse(
        "task.jinja2",
        {
            "request": request,
            "task": task,
            "referer": referer,
            "pretty_printed": json.dumps(task, indent=4, cls=JSONEncoderAdditionalTypes),
        },
    )
