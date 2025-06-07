import functools
import os
from typing import Any, Dict, List, Type

from .language import Language


def _is_reporter(cls: Type[Any]) -> bool:
    """We want to be able to check whether cls is a Reporter but without importing Reporter to
    avoid cyclical import."""

    if cls.__name__ == "Reporter":
        return True
    if cls != object:
        return any([_is_reporter(base) for base in cls.__bases__])
    return False


@functools.lru_cache(maxsize=1)
def get_all_reporters() -> List[Type[Any]]:
    """Finds all Reporters, i.e. all classes inheriting from Reporter in artemis.reporting.modules.*.reporter."""
    modules_dir = os.path.join(os.path.dirname(__file__), "..", "modules")
    reporters = []
    for item in os.listdir(modules_dir):
        if os.path.exists(os.path.join(modules_dir, item, "reporter.py")):
            import_result = __import__(f"artemis.reporting.modules.{item}.reporter")
            reporter_module = getattr(import_result.reporting.modules, item).reporter
            for module_item_name in dir(reporter_module):
                module_item = getattr(reporter_module, module_item_name)

                if isinstance(module_item, type) and _is_reporter(module_item) and module_item.__name__ != "Reporter":
                    reporters.append(module_item)
    return reporters


def assets_from_task_result(task_result: Dict[str, Any]) -> List[Any]:
    """
    Converts a task result as saved by an Artemis task to (one or many) found assets.
    """
    assets = []
    for reporter in get_all_reporters():
        assets.extend(reporter.get_assets(task_result))
    return assets


def reports_from_task_result(task_result: Dict[str, Any], language: Language) -> List[Any]:
    """
    Converts a task result as saved by an Artemis task to (one or many) filtered vulnerability reports.
    """
    reports = []
    for reporter in get_all_reporters():
        reports.extend(reporter.create_reports(task_result, language))
    return reports
