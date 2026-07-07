import asyncio
import datetime
import hmac
from typing import Annotated, Any, Dict, Optional, Type

import aiohttp
from fastapi import APIRouter, Body, Depends, Header, HTTPException
from fastapi.responses import Response
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from karton.core.task import TaskPriority as KartonTaskPriority
from pydantic import BaseModel
from redis import Redis

from artemis.blocklist import load_blocklist, should_block_scanning
from artemis.config import Config
from artemis.db import DB, ColumnOrdering, TaskFilter, TaskPriority
from artemis.frontend import build_export_zip_response
from artemis.karton_utils import get_binds_that_can_be_disabled, get_num_pending_tasks
from artemis.modules.base.module_runtime_configuration import (
    ModuleRuntimeConfiguration,
)
from artemis.modules.classifier import Classifier
from artemis.modules.runtime_configuration.mail_dns_scanner_configuration import (
    MailDNSScannerConfiguration,
)
from artemis.modules.runtime_configuration.nuclei_configuration import (
    NucleiConfiguration,
)
from artemis.producer import create_tasks
from artemis.reporting.base.language import Language
from artemis.templating import (
    dedent,
    render_markdown,
)

router = APIRouter()
db = DB()
redis = Redis.from_url(Config.Data.REDIS_CONN_STR)

RUNTIME_CONFIGURATION_CLASSES: Dict[str, Type[ModuleRuntimeConfiguration]] = {
    "mail_dns_scanner": MailDNSScannerConfiguration,
    "nuclei": NucleiConfiguration,
}


if Config.Miscellaneous.BLOCKLIST_FILE:
    BLOCKLIST = load_blocklist(Config.Miscellaneous.BLOCKLIST_FILE)
else:
    BLOCKLIST = []


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
    include_only_results_since: Optional[datetime.datetime]


def verify_api_token(x_api_token: Annotated[str, Header()]) -> None:
    if not Config.Miscellaneous.API_TOKEN:
        raise HTTPException(
            status_code=401,
            detail="Please fill the API_TOKEN variable in .env in order to use the API",
        )
    elif not hmac.compare_digest(x_api_token, Config.Miscellaneous.API_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid API token")


@router.post("/add", dependencies=[Depends(verify_api_token)])
def add(
    targets: list[str],
    tag: Optional[str] = Body(default=None),
    disabled_modules: Optional[list[str]] = Body(default=None),
    enabled_modules: Optional[list[str]] = Body(default=None),
    requests_per_second_override: Optional[float] = Body(default=None),
    priority: str = Body(default="normal"),
    module_runtime_configurations: Optional[Dict[str, Dict[str, Any]]] = Body(default=None),
) -> Dict[str, Any]:
    """Add targets to be scanned.

    You can provide per-task module configurations through the module_runtime_configurations parameter.
    These configurations control runtime behavior (like scan aggressiveness) for each module.
    """
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

    # Validate module configurations if provided
    if module_runtime_configurations:
        for module_name, config in module_runtime_configurations.items():
            config_class = RUNTIME_CONFIGURATION_CLASSES.get(module_name)
            if config_class:
                try:
                    config_instance = config_class.deserialize(config)
                    if not config_instance.validate():
                        raise ValueError(f"Invalid configuration for module {module_name}")
                except Exception as e:
                    raise HTTPException(status_code=400, detail=f"Invalid configuration for {module_name}: {str(e)}")
            else:
                raise HTTPException(status_code=400, detail=f"No runtime configuration class for {module_name}")
    else:
        module_runtime_configurations = {}

    task_ids = create_tasks(
        targets,
        tag,
        disabled_modules=disabled_modules,
        priority=KartonTaskPriority(priority),
        requests_per_second_override=requests_per_second_override,
        module_runtime_configurations=module_runtime_configurations,
    )

    return {"ok": True, "ids": task_ids}


@router.get("/analyses", dependencies=[Depends(verify_api_token)])
def list_analysis(tag: Optional[str] = None) -> list[Dict[str, Any]]:
    """Returns the list of analysed targets. Any scanned target would be listed here."""
    num_pending_tasks = get_num_pending_tasks(KartonBackend(config=KartonConfig()))
    if tag:
        analyses = db.get_analyses_by_tag(tag)
    else:
        analyses = db.list_analysis()
    for analysis in analyses:
        analysis["num_pending_tasks"] = num_pending_tasks.get(analysis["id"], 0)
    return analyses


@router.get("/analyses/reprioritize/{analysis_id}", dependencies=[Depends(verify_api_token)])
def reprioritize_analysis(analysis_id: str, new_priority: TaskPriority) -> Dict[str, bool]:
    """Enqueue a request to reprioritize a given analysis. The priority will be changed for all tasks of the analysis. Change might take some time to be reflected in the system."""
    db.set_analysis_desired_priority(analysis_id, new_priority)
    return {"ok": True}


@router.get("/get-modules-that-can-be-disabled", dependencies=[Depends(verify_api_token)])
def get_binds_that_can_be_disabled_endpoint() -> list[dict[str, str]]:
    """Returns the list of modules that can be disabled when adding a new scanning task."""
    return [
        {
            "identity": bind.identity,
            "info": render_markdown(dedent(bind.info)),
        }
        for bind in get_binds_that_can_be_disabled()
    ]


@router.get("/num-queued-tasks", dependencies=[Depends(verify_api_token)])
def num_queued_tasks(karton_names: Optional[list[str]] = None) -> int:
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
) -> list[Dict[str, Any]]:
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
def get_exports(tag_prefix: Optional[str] = None) -> list[ReportGenerationTaskModel]:
    """list all exports. An export is a request to create human-readable messages that may be sent to scanned entities."""
    return [
        ReportGenerationTaskModel(
            id=task.id,
            created_at=task.created_at,
            comment=task.comment,
            tag=task.tag,
            status=task.status,
            language=task.language,
            include_only_results_since=task.include_only_results_since,
            skip_previously_exported=task.skip_previously_exported,
            zip_url=f"/api/export/download-zip/{task.id}" if task.output_location else None,
            error=task.error,
            alerts=task.alerts,
        )
        for task in db.list_report_generation_tasks(tag_prefix=tag_prefix)
    ]


@router.get("/is-blocklisted/{domain}", dependencies=[Depends(verify_api_token)])
def is_blocklisted(domain: str) -> bool:
    """Returns True if scanning of a given domain is blocklisted"""
    return should_block_scanning(domain=domain, ip=None, karton_name=None, blocklist=BLOCKLIST)


@router.get("/export/download-zip/{id}", dependencies=[Depends(verify_api_token)])
def download_zip(id: int) -> Response:
    """Download a zip file containing an export - all messages that can be sent to scanned entities + additional data such as statistics."""
    return build_export_zip_response(id)


@router.post("/export/delete/{id}", dependencies=[Depends(verify_api_token)])
async def post_export_delete(id: int) -> Dict[str, Any]:
    """Delete an export."""
    await asyncio.to_thread(db.delete_report_generation_task, id)
    return {
        "ok": True,
    }


@router.post("/build-html-message", dependencies=[Depends(verify_api_token)])
async def post_build_html_message(language: str = Body(), data: Dict[str, Any] = Body()) -> str:
    """Renders a custom list of vulnerabilities as HTML."""
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        async with session.post(
            "http://autoreporter:5000/api/build-html-message",
            json={
                "language": language,
                "data": data,
            },
        ) as response:
            response.raise_for_status()
            return await response.json()  # type: ignore


@router.post("/export", dependencies=[Depends(verify_api_token)])
async def post_export(
    language: str = Body(),
    skip_previously_exported: bool = Body(),
    tag: Optional[str] = Body(None),
    comment: Optional[str] = Body(None),
    custom_template_arguments: Dict[str, Any] = Body({}),
    include_only_results_since: Optional[datetime.datetime] = Body(None),
    skip_hooks: bool = Body(False),
    skip_suspicious_reports: bool = Body(False),
) -> Dict[str, Any]:
    """Create a new export. An export is a request to create human-readable messages that may be sent to scanned entities."""
    await asyncio.to_thread(
        db.create_report_generation_task,
        skip_previously_exported=skip_previously_exported,
        tag=tag,
        comment=comment,
        custom_template_arguments=custom_template_arguments,
        language=Language(language),
        skip_hooks=skip_hooks,
        include_only_results_since=include_only_results_since,
        skip_suspicious_reports=skip_suspicious_reports,
    )
    return {
        "ok": True,
    }
