from os import path

from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = path.join(path.dirname(__file__), "..", "templates")
TEMPLATES = Jinja2Templates(directory=TEMPLATES_DIR)
