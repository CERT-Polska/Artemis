import html
import textwrap
from os import path
from typing import Any, Dict, List

import markdown
from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = path.join(path.dirname(__file__), "..", "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

TEMPLATE_TASK_TABLE_ROW_TASK_LINK = templates.get_template("table_row/task/task_link.jinja2")
TEMPLATE_TASK_TABLE_ROW_BADGES = templates.get_template("table_row/task/badges.jinja2")

TEMPLATE_ANALYSIS_TABLE_ROW_PENDING_TASKS = templates.get_template("table_row/analysis/pending_tasks.jinja2")
TEMPLATE_ANALYSIS_TABLE_ROW_ACTIONS = templates.get_template("table_row/analysis/actions.jinja2")


def dedent(text: str) -> str:
    if not text:
        return ""
    return textwrap.dedent(text)


def render_markdown(markdown_text: str) -> str:
    if not markdown_text:
        return ""
    return markdown.markdown(markdown_text)


templates.env.filters["dedent"] = dedent
templates.env.filters["render_markdown"] = render_markdown


def render_task_table_row(task_result: Dict[str, Any]) -> List[str]:
    return [
        html.escape(task_result["created_at"].strftime("%Y-%m-%d %H:%M:%S")) if "created_at" in task_result else None,
        html.escape(task_result["tag"] or ""),
        html.escape(task_result["receiver"]),
        TEMPLATE_TASK_TABLE_ROW_TASK_LINK.render({"task_result": task_result}),
        TEMPLATE_TASK_TABLE_ROW_BADGES.render({"task_result": task_result}),
        html.escape(task_result.get("status_reason") or ""),
    ]


def render_analyses_table_row(entry: Dict[str, Any]) -> List[str]:
    return [
        html.escape(entry["target"]),
        html.escape(entry["tag"] or ""),
        TEMPLATE_ANALYSIS_TABLE_ROW_PENDING_TASKS.render({"entry": entry}),
        TEMPLATE_ANALYSIS_TABLE_ROW_ACTIONS.render({"entry": entry}),
    ]
