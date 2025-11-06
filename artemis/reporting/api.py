import os
import tempfile
from pathlib import Path
from typing import Any, Dict

import uvicorn
from fastapi import APIRouter, Body, FastAPI

from artemis.reporting.base.language import Language
from artemis.reporting.export.main import (
    build_message_template_and_print_path,
    install_translations_and_print_path,
)

router = APIRouter()


@router.post("/build-html-message")
async def post_build_html_message(language: str = Body(), data: Dict[str, Any] = Body()) -> str:
    """
    Renders a custom list of vulnerabilities as HTML.

    This needs to be an API endpoint of autoreporter, not web, as autoreporter has mounted all files
    related to building reports for custom modules (e.g. Artemis-modules-extra).
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        os.makedirs(Path(tmp_dir) / "advanced")
        message_template = build_message_template_and_print_path(Path(tmp_dir), silent=True)
        install_translations_and_print_path(Language(language), Path(tmp_dir), silent=True)
        return message_template.render({"data": data})


app = FastAPI(
    docs_url=None,
    redoc_url=None,
)

app.include_router(router, prefix="/api")


def run() -> None:
    uvicorn.run(app, host="0.0.0.0", port=5000)
