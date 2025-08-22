import os
from pathlib import Path
from typing import IO, Any

from artemis.module_base import ArtemisBase

# By default, these variables are required by the modules. As we are importing the modules
# only to get the docs, let's mock them.
os.environ["DB_CONN_STR"] = ""
os.environ["POSTGRES_CONN_STR"] = ""
os.environ["REDIS_CONN_STR"] = "redis://127.0.0.1"

from sphinx.application import Sphinx  # type: ignore # noqa


def setup(app: Sphinx) -> None:
    app.connect("config-inited", on_config_inited)


def on_config_inited(_1: Any, _2: Any) -> None:
    output = Path(__file__).parents[0] / "module-list.inc"

    with open(output, "w") as f:
        print_module_docs(output_file=f)


def print_module_docs(output_file: IO[str]) -> None:
    module_docs = {}
    for module_name in os.listdir(Path(__file__).parents[0] / ".." / "artemis" / "modules"):
        if module_name.startswith("__") or not module_name.endswith(".py"):
            continue

        module_name = module_name.removesuffix(".py")

        imported_module = __import__("artemis.modules." + module_name)
        imported_module = getattr(imported_module.modules, module_name)

        for item in dir(imported_module):
            attribute = getattr(imported_module, item)
            if isinstance(attribute, type) and issubclass(attribute, ArtemisBase) and attribute != ArtemisBase:
                if not hasattr(attribute, "original_doc") and attribute.__name__.startswith("Base"):
                    continue

                if attribute.identity in ["classifier", "http_service_to_url"]:
                    continue

                module_docs[attribute.identity] = attribute.original_doc.strip().replace("\n", " ")  # type: ignore

    for item in sorted(module_docs.keys(), key=lambda key: key.lower()):
        output_file.write(item + "\n")
        output_file.write("^" * len(item) + "\n")
        # RST uses double backticks for code
        output_file.write(module_docs[item].replace("`", "``") + "\n")
        output_file.write("\n")
