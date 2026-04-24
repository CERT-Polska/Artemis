import base64
import hmac
import os

from fastapi import Request
from fastapi.responses import RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from artemis.config import Config

SESSION_KEY_AUTHENTICATED = "authenticated"

# Paths that bypass the frontend session check: /api/* has its own X-API-Token
# auth, /static/* must stay reachable so that the login page can load its own
# CSS, and /login and /logout are the auth endpoints themselves.
UNPROTECTED_PATH_PREFIXES = ("/api/", "/static/")
UNPROTECTED_PATHS = ("/login", "/logout")


def generate_session_secret() -> str:
    session_secret_path = "/data/session_secret"

    if os.path.exists(session_secret_path):
        with open(session_secret_path) as f:
            return f.read()

    secret = base64.b64encode(os.urandom(32))

    # This will raise if someone else is also creating the secret
    fd = os.open(session_secret_path, os.O_RDWR | os.O_CREAT | os.O_EXCL)
    os.write(fd, secret)
    os.close(fd)

    return secret.decode("ascii")


def frontend_credentials_configured() -> bool:
    return bool(Config.Miscellaneous.FRONTEND_USERNAME and Config.Miscellaneous.FRONTEND_PASSWORD)


def check_credentials(username: str, password: str) -> bool:
    if not frontend_credentials_configured():
        return False

    # Compare both halves in constant time - short-circuiting on the username would
    # leak its validity through response timing.
    username_ok = hmac.compare_digest(username, Config.Miscellaneous.FRONTEND_USERNAME)
    password_ok = hmac.compare_digest(password, Config.Miscellaneous.FRONTEND_PASSWORD)
    return username_ok and password_ok


class FrontendAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        if path in UNPROTECTED_PATHS or any(path.startswith(prefix) for prefix in UNPROTECTED_PATH_PREFIXES):
            return await call_next(request)

        if request.session.get(SESSION_KEY_AUTHENTICATED):
            return await call_next(request)

        return RedirectResponse(url="/login", status_code=303)
