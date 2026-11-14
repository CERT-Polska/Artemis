import math
import shutil
import time
from typing import Optional

import psutil
import requests
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from karton.core.backend import KartonBackend
from karton.core.config import Config as KartonConfig
from redis import Redis, RedisError

from artemis.api import verify_api_token
from artemis.config import Config
from artemis.task_utils import LAST_CONSUMED_TASK_TIME_KEY

router = APIRouter()
redis = Redis.from_url(Config.Data.REDIS_CONN_STR)
_backend: KartonBackend | None = None


def _karton_backend() -> KartonBackend:
    global _backend
    if _backend is None:
        _backend = KartonBackend(config=KartonConfig())
    return _backend


@router.get("/health", dependencies=[Depends(verify_api_token)])
def health() -> JSONResponse:
    """Check host resources, scanning worker consumption, and the optional scanned assets API.

    last_consumed_task_time is the latest valid Unix timestamp among modules
    with queued tasks, or null if unavailable. Queued work is unhealthy only
    when none of these modules has consumed a task recently.
    """
    errors: dict[str, str] = {}
    memory = psutil.virtual_memory()
    disk_path = Config.Health.HEALTH_DISK_PATH
    disk = shutil.disk_usage(disk_path)
    if memory.available / memory.total * 100 < Config.Health.HEALTH_MIN_AVAILABLE_MEMORY_PERCENT:
        errors["memory"] = (
            f"Available RAM is {memory.available / memory.total:.2%}; "
            f"at least {Config.Health.HEALTH_MIN_AVAILABLE_MEMORY_PERCENT:g}% is required"
        )
    if disk.free / disk.total * 100 < Config.Health.HEALTH_MIN_FREE_DISK_PERCENT:
        errors["disk"] = (
            f"Free space on {disk_path} is {disk.free / disk.total:.1%}; "
            f"at least {Config.Health.HEALTH_MIN_FREE_DISK_PERCENT:g}% is required"
        )

    last_consumed_task_time: Optional[float] = None
    try:
        backend = _karton_backend()
        queued_by_module: dict[str, int] = {}
        for bind in backend.get_binds():
            queued = sum(backend.redis.llen(name) for name in backend.get_queue_names(bind.identity))
            if queued:
                queued_by_module[bind.identity] = queued

        for identity in queued_by_module:
            stored_time = redis.hget(LAST_CONSUMED_TASK_TIME_KEY, identity)
            timestamp = None
            if stored_time is not None:
                try:
                    timestamp = float(stored_time)
                    if not math.isfinite(timestamp):
                        timestamp = None
                except ValueError:
                    pass
            if timestamp is not None:
                if last_consumed_task_time is None:
                    last_consumed_task_time = timestamp
                else:
                    last_consumed_task_time = max(last_consumed_task_time, timestamp)
    except RedisError:
        errors["worker"] = "Unable to read task queues or consumption timestamps from Redis"
    except RuntimeError:
        errors["worker"] = "Unable to initialize or access the Karton backend"
    else:
        cutoff = time.time() - Config.Health.HEALTH_MAX_TASK_INACTIVITY_SECONDS
        if queued_by_module and (last_consumed_task_time is None or last_consumed_task_time < cutoff):
            errors["worker"] = (
                f"No tasks consumed in the last {Config.Health.HEALTH_MAX_TASK_INACTIVITY_SECONDS / 3600:g} hours"
            )

    assets_api_url = Config.ScannedAssetsAPI.SCANNED_ASSETS_API_URL
    if assets_api_url:
        try:
            response = requests.get(
                f"{assets_api_url.rstrip('/')}/health",
                timeout=Config.Limits.REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            if response.json()["status"] != "ok":
                errors["scanned_assets_api"] = "Additional scanned assets API health check failed"
        except requests.RequestException:
            errors["scanned_assets_api"] = "Additional scanned assets API health check failed"

    if errors:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "errors": errors, "last_consumed_task_time": last_consumed_task_time},
        )
    return JSONResponse(content={"status": "ok", "last_consumed_task_time": last_consumed_task_time})
