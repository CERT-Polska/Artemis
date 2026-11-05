import math
import shutil
import time

import psutil
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
    """Check available host RAM, configured disk space, and scanning worker consumption.

    last_consumed_task_time maps queued module identities to Unix timestamps
    (or null if unavailable). Only modules with queued tasks are checked for
    missing, invalid, or stale consumption timestamps.
    """
    errors: dict[str, str | dict[str, str]] = {}
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

    last_consumed_task_time: dict[str, float | None] = {}
    worker_errors: dict[str, str] = {}
    try:
        backend = _karton_backend()
        queued_by_module: dict[str, int] = {}
        for bind in backend.get_binds():
            queued = sum(backend.redis.llen(name) for name in backend.get_queue_names(bind.identity))
            if queued:
                queued_by_module[bind.identity] = queued

        cutoff = time.time() - Config.Health.HEALTH_MAX_TASK_INACTIVITY_SECONDS
        for identity, queued in queued_by_module.items():
            stored_time = redis.hget(LAST_CONSUMED_TASK_TIME_KEY, identity)
            timestamp = None
            if stored_time is not None:
                try:
                    timestamp = float(stored_time)
                    if not math.isfinite(timestamp):
                        timestamp = None
                except ValueError:
                    pass
            last_consumed_task_time[identity] = timestamp
            if timestamp is None or timestamp < cutoff:
                worker_errors[identity] = (
                    f"{queued} tasks queued, but none consumed in the last "
                    f"{Config.Health.HEALTH_MAX_TASK_INACTIVITY_SECONDS / 3600:g} hours"
                )
        if worker_errors:
            errors["worker"] = worker_errors
    except RedisError:
        errors["worker"] = "Unable to read task queues or consumption timestamps from Redis"
    except RuntimeError:
        errors["worker"] = "Unable to initialize or access the Karton backend"

    if errors:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "errors": errors, "last_consumed_task_time": last_consumed_task_time},
        )
    return JSONResponse(content={"status": "ok", "last_consumed_task_time": last_consumed_task_time})
