import base64
import hmac
import os
import secrets

from fastapi import Request
from fastapi.responses import RedirectResponse, Response
from redis import Redis
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from artemis.config import Config

SESSION_KEY_ID = "session_id"

# The session cookie is only signed - it is not possible to revoke it by itself. Therefore, on login we additionally
# store the session id in Redis, and the cookie is accepted only as long as the id is there (so that e.g. logging out
# invalidates a stolen cookie).
SESSION_REDIS_KEY_PREFIX = "artemis-frontend-session:"
SESSION_MAX_AGE_SECONDS = 14 * 24 * 60 * 60

_redis = Redis.from_url(Config.Data.REDIS_CONN_STR)

# Paths that bypass the frontend session check: /api/* has its own X-API-Token
# auth, /static/* must stay reachable so that the login page can load its own
# CSS, and /login and /logout are the auth endpoints themselves.
UNPROTECTED_PATH_PREFIXES = ("/api/", "/static/")
UNPROTECTED_PATHS = ("/login", "/logout")


def generate_session_secret() -> str:
    session_secret_path = "/data/session_secret"

    if os.path.exists(session_secret_path):
        with open(session_secret_path) as f:
            secret = f.read()
        if secret:
            return secret

    secret = base64.b64encode(os.urandom(32)).decode("ascii")

    # This will raise if someone else is also creating the secret
    fd = os.open(session_secret_path, os.O_RDWR | os.O_CREAT | os.O_EXCL)
    os.write(fd, secret.encode("ascii"))
    os.close(fd)

    return secret


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


def create_session(request: Request) -> None:
    """Marks the current session as authenticated."""
    session_id = secrets.token_urlsafe(32)
    _redis.set(SESSION_REDIS_KEY_PREFIX + session_id, 1, ex=SESSION_MAX_AGE_SECONDS)
    request.session[SESSION_KEY_ID] = session_id


def is_authenticated(request: Request) -> bool:
    session_id = request.session.get(SESSION_KEY_ID)
    if not session_id:
        return False

    # Refreshes the expiration time (in the same way the cookie expiration time is refreshed on each request).
    # Returns False if the session doesn't exist (e.g. has been destroyed by logging out).
    return bool(_redis.expire(SESSION_REDIS_KEY_PREFIX + session_id, SESSION_MAX_AGE_SECONDS))


def destroy_session(request: Request) -> None:
    session_id = request.session.get(SESSION_KEY_ID)
    if session_id:
        _redis.delete(SESSION_REDIS_KEY_PREFIX + session_id)
    request.session.clear()


class FrontendAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path

        if path in UNPROTECTED_PATHS or any(path.startswith(prefix) for prefix in UNPROTECTED_PATH_PREFIXES):
            return await call_next(request)

        if is_authenticated(request):
            return await call_next(request)

        return RedirectResponse(url="/login", status_code=303)
