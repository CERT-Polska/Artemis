from os import path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from artemis.api import router as router_api
from artemis.db import DB
from artemis.frontend import router as router_front

app = FastAPI()
db = DB()

# We run it here so that it will get executed even when importing from main,
# which will happen when running the app via `uvicorn artemis.main:app`
db.initialize_database()

app.include_router(router_front, prefix="")
app.include_router(router_api, prefix="/api")
app.mount(
    "/static", StaticFiles(directory=path.join(path.dirname(__file__), "..", "static"))
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
