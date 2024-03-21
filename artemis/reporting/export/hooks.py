import functools
import os
from pathlib import Path
from typing import List, Type

from artemis import utils
from artemis.reporting.export.export_data import ExportData
from artemis.reporting.export.hook import ExportHook

logger = utils.build_logger(__name__)


@functools.lru_cache(maxsize=1)
def get_all_hooks() -> List[Type[ExportHook]]:
    """Finds all ExportHooks, i.e. all classes inheriting from ExportHook in artemis.reporting.export.hook_modules."""
    modules_dir = os.path.join(os.path.dirname(__file__), "hook_modules")
    for item in os.listdir(modules_dir):
        if item.endswith(".py") and item != "__init__.py":
            module_name = item.removesuffix(".py")
            __import__(f"artemis.reporting.export.hook_modules.{module_name}")
    return sorted(ExportHook.__subclasses__(), key=lambda cls: cls.get_ordering())


def run_export_hooks(output_dir: Path, export_data: ExportData, silent: bool) -> None:
    for hook in get_all_hooks():
        logger.info("Running hook: %s (ordering=%s)", hook.__name__, hook.get_ordering())
        hook.run(output_dir, export_data, silent)
