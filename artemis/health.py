import math
import shutil
import time

import psutil
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from redis import Redis, RedisError

from artemis.api import verify_api_token
from artemis.config import Config
from artemis.task_utils import LAST_CONSUMED_TASK_TIME_KEY

router = APIRouter()
redis = Redis.from_url(Config.Data.REDIS_CONN_STR)
MAX_TASK_INACTIVITY_SECONDS = 4 * 60 * 60


@router.get("/health", dependencies=[Depends(verify_api_token)])
def health() -> JSONResponse:
    """Check available RAM, root disk space, and consumption across scanning workers.

    last_consumed_task_time is Unix time in seconds, or null if unavailable.
    Workers that have never consumed a task are unhealthy, as are idle workers.
    """
    errors = {}
    memory = psutil.virtual_memory()
    disk = shutil.disk_usage("/")
    if memory.available / memory.total < 0.2:
        errors["memory"] = f"Available RAM is {memory.available / memory.total:.2%}; at least 20% is required"
    if disk.free / disk.total < 0.2:
        errors["disk"] = f"Free space on / is {disk.free / disk.total:.1%}; at least 20% is required"

    last_consumed_task_time = None
    try:
        stored_time = redis.get(LAST_CONSUMED_TASK_TIME_KEY)
        if stored_time is None:
            errors["worker"] = "No task consumption has been recorded"
        else:
            last_consumed_task_time = float(stored_time)
            if not math.isfinite(last_consumed_task_time):
                raise ValueError("Non-finite task consumption timestamp")
            if last_consumed_task_time < time.time() - MAX_TASK_INACTIVITY_SECONDS:
                errors["worker"] = "No task has been consumed in the last 4 hours"
    except RedisError:
        errors["worker"] = "Unable to read last_consumed_task_time from Redis"
    except ValueError:
        last_consumed_task_time = None
        errors["worker"] = "Invalid last_consumed_task_time stored in Redis"

    if errors:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "errors": errors, "last_consumed_task_time": last_consumed_task_time},
        )
    return JSONResponse(content={"status": "ok", "last_consumed_task_time": last_consumed_task_time})
