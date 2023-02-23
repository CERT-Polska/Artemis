import html
from os import path
from typing import Any, Dict, List

from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = path.join(path.dirname(__file__), "..", "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

TEMPLATE_TABLE_ROW_TASK_LINK = templates.get_template("table_row/task_link.jinja2")
TEMPLATE_TABLE_ROW_BADGES = templates.get_template("table_row/badges.jinja2")


def render_table_row(task: Dict[str, Any]) -> List[str]:
    return [
        html.escape(task["created_at"].strftime("%Y-%m-%d %H:%M:%S"))
        if "created_at" in task
        else None,
        html.escape(task["headers"]["receiver"]),
        TEMPLATE_TABLE_ROW_TASK_LINK.render({"task": task}),
        TEMPLATE_TABLE_ROW_BADGES.render({"task": task}),
        task["status_reason"],
    ]
