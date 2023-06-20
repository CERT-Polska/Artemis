from typing import Dict


def parse_custom_template_arguments(arguments: str) -> Dict[str, str]:
    """Parses custom template arguments in the form of name1=value1,name2=value2,..."""
    arguments_parsed = {}
    for name_and_value in arguments.split(","):
        name_and_value = name_and_value.strip()

        if not name_and_value:
            continue

        if "=" not in name_and_value:
            raise ValueError("Expected custom_template_arguments to have the form of name1=value1,name2=value2,...")

        name, value = name_and_value.split("=", 1)
        arguments_parsed[name] = value
    return arguments_parsed
