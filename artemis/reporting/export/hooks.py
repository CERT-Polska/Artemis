import functools
import os
from pathlib import Path
from typing import List, Type

from artemis.reporting.export.export_data import ExportData
from artemis.reporting.export.hook import ExportHook


@functools.lru_cache(maxsize=1)
def get_all_hooks() -> List[Type[ExportHook]]:
    """Finds all ExportHooks, i.e. all classes inheriting from ExportHook in artemis.reporting.export.hook_modules."""
    modules_dir = os.path.join(os.path.dirname(__file__), "hook_modules")
    for item in os.listdir(modules_dir):
        if item.endswith(".py") and item != "__init__.py":
            module_name = item.removesuffix(".py")
            __import__(f"artemis.reporting.export.hook_modules.{module_name}")
    return ExportHook.__subclasses__()


def run_export_hooks(output_dir: Path, export_data: ExportData) -> None:
    for hook in get_all_hooks():
        hook.run(output_dir, export_data)
