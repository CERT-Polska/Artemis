import faulthandler
import signal
from os import path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi_csrf_protect.exceptions import CsrfProtectError
from starlette.middleware.sessions import SessionMiddleware

from artemis import csrf
from artemis.api import router as router_api
from artemis.auth import FrontendAuthMiddleware, generate_session_secret
from artemis.config import Config
from artemis.db import DB
from artemis.frontend import error_content_not_found
from artemis.frontend import router as router_front

faulthandler.register(signal.SIGUSR1)

app = FastAPI(
    docs_url="/docs" if Config.Miscellaneous.API_TOKEN else None,
    redoc_url=None,
)
app.exception_handler(CsrfProtectError)(csrf.csrf_protect_exception_handler)
app.exception_handler(404)(error_content_not_found)

# Middleware is applied bottom-up: SessionMiddleware must wrap FrontendAuthMiddleware
# so that request.session is populated by the time the auth check runs.
app.add_middleware(FrontendAuthMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=generate_session_secret(),
    session_cookie="artemis_session",
    same_site="strict",
    https_only=False,
)

db = DB()

app.include_router(router_front, prefix="")
app.include_router(router_api, prefix="/api")
app.mount("/static", StaticFiles(directory=path.join(path.dirname(__file__), "..", "static")), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
