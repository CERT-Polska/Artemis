import textwrap
from typing import get_type_hints

from artemis.config import DEFAULTS, Config


def print_docs_for_class(cls: type, depth: int = 0) -> None:
    print(cls.__name__)

    header_characters = '-^"'
    print(header_characters[depth] * len(cls.__name__))
    print()

    hints = get_type_hints(cls, include_extras=True)
    for variable_name in dir(cls):
        if variable_name.startswith("__"):
            continue

        member = getattr(cls, variable_name)
        if isinstance(member, type):
            print_docs_for_class(member, depth + 1)
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

        print(
            textwrap.dedent(
                f"""
                {variable_name}\n{default_str}{doc}
            """.strip()
            )
        )
        print()


print_docs_for_class(Config)
