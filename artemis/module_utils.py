import os

from artemis.utils import build_logger


def try_to_import_all_modules() -> None:
    logger = build_logger(__name__)
    modules_dir = os.path.join(os.path.dirname(__file__), "modules")
    for item in os.listdir(modules_dir):
        if item.endswith(".py"):
            module_name = f"artemis.modules.{item[:-3]}"
            try:
                __import__(module_name)
            except Exception:
                logger.exception("Unable to import module: %s", module_name)
