import html
from os import path
from typing import Any, Dict, List

from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = path.join(path.dirname(__file__), "..", "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

TEMPLATE_TASK_TABLE_ROW_TASK_LINK = templates.get_template("table_row/task/task_link.jinja2")
TEMPLATE_TASK_TABLE_ROW_BADGES = templates.get_template("table_row/task/badges.jinja2")

TEMPLATE_ANALYSIS_TABLE_ROW_PENDING_TASKS = templates.get_template("table_row/analysis/pending_tasks.jinja2")
TEMPLATE_ANALYSIS_TABLE_ROW_RESULTS_LINK = templates.get_template("table_row/analysis/results_link.jinja2")


def render_task_table_row(task: Dict[str, Any]) -> List[str]:
    return [
        html.escape(task["created_at"].strftime("%Y-%m-%d %H:%M:%S")) if "created_at" in task else None,
        html.escape(task["payload_persistent"].get("tag", "")),
        html.escape(task["headers"]["receiver"]),
        TEMPLATE_TASK_TABLE_ROW_TASK_LINK.render({"task": task}),
        TEMPLATE_TASK_TABLE_ROW_BADGES.render({"task": task}),
        html.escape(task.get("status_reason") or ""),
    ]


def render_analyses_table_row(entry: Dict[str, Any]) -> List[str]:
    return [
        html.escape(entry["payload"]["data"]),
        html.escape(entry["payload_persistent"].get("tag", "")),
        TEMPLATE_ANALYSIS_TABLE_ROW_PENDING_TASKS.render({"entry": entry}),
        TEMPLATE_ANALYSIS_TABLE_ROW_RESULTS_LINK.render({"entry": entry}),
    ]
