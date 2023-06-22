import functools
import os
from typing import List, Type

from artemis.reporting.export.export_data import ExportData
from artemis.reporting.export.hook import ExportHook


@functools.lru_cache(maxsize=1)
def get_all_hooks() -> List[Type[ExportHook]]:
    """Finds all ExportHooks, i.e. all classes inheriting from ExportHook in artemis.reporting.export.hook_modules."""
    modules_dir = os.path.join(os.path.dirname(__file__), "hook_modules")
    hooks = []
    for item in os.listdir(modules_dir):
        if item.endswith(".py") and item != "__init__.py":
            module_name = item.split(".")[0]
            import_result = __import__(f"artemis.reporting.export.hook_modules.{module_name}")
            hook_module = getattr(import_result.reporting.export.hook_modules, module_name)
            for module_item_name in dir(hook_module):
                module_item = getattr(hook_module, module_item_name)

                if isinstance(module_item, type) and issubclass(module_item, ExportHook) and module_item != ExportHook:
                    hooks.append(module_item)
    return hooks


def run_export_hooks(output_dir: str, export_data: ExportData) -> None:
    for hook in get_all_hooks():
        hook.run(output_dir, export_data)
