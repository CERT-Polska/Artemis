import hmac
from typing import Annotated

from fastapi import Header, HTTPException

from artemis.config import Config


def verify_api_token(x_api_token: Annotated[str, Header()]) -> None:
    if not Config.Miscellaneous.API_TOKEN:
        raise HTTPException(
            status_code=401,
            detail="Please fill the API_TOKEN variable in .env in order to use the API",
        )
    elif not hmac.compare_digest(x_api_token, Config.Miscellaneous.API_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid API token")
