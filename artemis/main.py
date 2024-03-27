from os import path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi_csrf_protect.exceptions import CsrfProtectError

from artemis import csrf, db_migration
from artemis.api import router as router_api
from artemis.config import Config
from artemis.db import DB
from artemis.frontend import error_content_not_found
from artemis.frontend import router as router_front
from artemis.utils import read_template

app = FastAPI(
    docs_url="/docs" if Config.Miscellaneous.API_TOKEN else None,
    redoc_url=None,
    # This will be displayed as the additional text in Swagger docs
    description=read_template("components/generating_reports_hint.jinja2"),
)
app.exception_handler(CsrfProtectError)(csrf.csrf_protect_exception_handler)
app.exception_handler(404)(error_content_not_found)

db = DB()

# We run it here so that it will get executed even when importing from main,
# which will happen when running the app via `uvicorn artemis.main:app`
db_migration.migrate_and_start_thread()

app.include_router(router_front, prefix="")
app.include_router(router_api, prefix="/api")
app.mount("/static", StaticFiles(directory=path.join(path.dirname(__file__), "..", "static")))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
