import base64
import os
from functools import wraps
from typing import Any, Dict

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError
from pydantic import BaseModel

from artemis.templating import templates


def generate_csrf_secret() -> str:
    csrf_secret_path = "/data/csrf_secret"

    if os.path.exists(csrf_secret_path):
        with open(csrf_secret_path) as f:
            return f.read()

    secret = base64.b64encode(os.urandom(32))

    # This will raise if someone else is also creating the token
    fd = os.open(csrf_secret_path, os.O_RDWR | os.O_CREAT | os.O_EXCL)
    os.write(fd, secret)
    os.close(fd)

    return secret.decode("ascii")


class CsrfSettings(BaseModel):
    secret_key: str = generate_csrf_secret()
    cookie_samesite: str = "strict"
    token_location: str = "body"
    token_key: str = "csrf_token"


@CsrfProtect.load_config  # type: ignore
def get_csrf_config() -> CsrfSettings:
    return CsrfSettings()


def csrf_form_template_response(template_name: str, context: Dict[str, Any], csrf_protect: CsrfProtect) -> Response:
    csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
    context["csrf_token"] = csrf_token
    response = templates.TemplateResponse(template_name, context)
    csrf_protect.set_csrf_cookie(signed_token, response)
    return response


def validate_csrf(func: Any) -> Any:
    @wraps(func)
    async def wrapper(request: Request, csrf_protect: CsrfProtect, *args: Any, **kwargs: Any) -> Any:
        await csrf_protect.validate_csrf(request)
        return await func(request, *args, **kwargs)

    return wrapper


def csrf_protect_exception_handler(request: Request, exc: CsrfProtectError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})
