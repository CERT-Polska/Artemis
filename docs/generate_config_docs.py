import os
import textwrap
from pathlib import Path
from typing import IO, Any, get_type_hints

# By default, these variables are required by config. As we are importing the config
# only to get the docs, let's mock them.
os.environ["DB_CONN_STR"] = ""
os.environ["POSTGRES_CONN_STR"] = ""
os.environ["REDIS_CONN_STR"] = "redis://127.0.0.1"
from config import DEFAULTS, Config  # type: ignore # noqa
from sphinx.application import Sphinx  # type: ignore # noqa


def setup(app: Sphinx) -> None:
    app.connect("config-inited", on_config_inited)


def on_config_inited(_1: Any, _2: Any) -> None:
    output = Path(__file__).parents[0] / "user-guide" / "config-docs.inc"

    with open(output, "w") as f:
        print_docs_for_class(Config, output_file=f)


def print_docs_for_class(cls: type, output_file: IO[str], depth: int = 0) -> None:
    if depth > 0:
        output_file.write(cls.__name__ + "\n")

        header_characters = '-^"'
        output_file.write(header_characters[depth - 1] * len(cls.__name__) + "\n\n")

    hints = get_type_hints(cls, include_extras=True)
    for variable_name in dir(cls):
        if variable_name.startswith("__"):
            continue

        member = getattr(cls, variable_name)
        if isinstance(member, type):
            print_docs_for_class(member, output_file, depth + 1)
            continue
        elif member == Config.verify_each_variable_is_annotated:
            continue

        (hint,) = hints[variable_name].__metadata__
        indent = 4 * " "
        doc = "\n".join(textwrap.wrap(hint.strip(), width=100, initial_indent=indent, subsequent_indent=indent))
        if variable_name in DEFAULTS:
            default_str = f"{indent}Default: {DEFAULTS[variable_name]}\n\n"
        else:
            default_str = ""

        output_file.write(
            textwrap.dedent(
                f"""
                    {variable_name}\n{default_str}{doc}
                """.strip()
            )
            + "\n\n"
        )
