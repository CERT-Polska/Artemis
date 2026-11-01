import shutil

import psutil
from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/health")
def health() -> JSONResponse:
    """Require at least 20% available RAM and free space on the root filesystem."""
    memory = psutil.virtual_memory()
    disk = shutil.disk_usage("/")
    problems = []
    if memory.available / memory.total < 0.2:
        problems.append("Available RAM is below 20%")
    if disk.free / disk.total < 0.2:
        problems.append("Free disk space is below 20%")

    if problems:
        return JSONResponse(status_code=503, content={"error": "; ".join(problems)})
    return JSONResponse(content={"status": "ok"})
