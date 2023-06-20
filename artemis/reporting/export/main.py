import dataclasses
import datetime
import json
import os
from pathlib import Path
from typing import Optional

import termcolor
import typer
from jinja2 import BaseLoader, Environment, StrictUndefined, Template

from artemis.db import DB
from artemis.json_utils import JSONEncoderAdditionalTypes
from artemis.reporting.base.language import Language
from artemis.reporting.base.templating import build_message_template
from artemis.reporting.blocklist import load_blocklist
from artemis.reporting.export.common import OUTPUT_LOCATION
from artemis.reporting.export.custom_template_arguments import (
    parse_custom_template_arguments,
)
from artemis.reporting.export.db import DataLoader
from artemis.reporting.export.export_data import ExportData, build_export_data
from artemis.reporting.export.long_unseen_report_types import (
    print_long_unseen_report_types,
)
from artemis.reporting.export.previous_reports import load_previous_reports
from artemis.reporting.export.stats import print_and_save_stats
from artemis.reporting.export.translations import install_translations

environment = Environment(
    loader=BaseLoader(), extensions=["jinja2.ext.i18n"], undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True
)


HOST_ROOT_PATH = "/host-root/"


def _build_message_template_and_print_path(date_str: str) -> Template:
    output_message_template_file_name = os.path.join(OUTPUT_LOCATION, "message_template_" + date_str + ".jinja2")

    message_template_content = build_message_template()
    message_template = environment.from_string(message_template_content)

    with open(output_message_template_file_name, "w") as f:
        f.write(message_template_content)

    print(f"Message template written to file: {output_message_template_file_name}")
    return message_template


def _install_translations_and_print_path(language: Language, date_str: str) -> None:
    translations_file_name = os.path.join(OUTPUT_LOCATION, "translations_" + date_str + ".po")
    compiled_translations_file_name = os.path.join(OUTPUT_LOCATION, "compiled_translations_" + date_str + ".mo")
    install_translations(language, environment, translations_file_name, compiled_translations_file_name)

    print(f"Translations written to file: {translations_file_name}")
    print(f"Compiled translations written to file: {compiled_translations_file_name}")


def _dump_export_data_and_print_path(export_data: ExportData, date_str: str) -> None:
    output_json_file_name = os.path.join(OUTPUT_LOCATION, "output_" + date_str + ".json")

    with open(output_json_file_name, "w") as f:
        json.dump(export_data, f, indent=4, cls=JSONEncoderAdditionalTypes)

    print(f"JSON written to file: {output_json_file_name}")


def _build_messages_and_print_path(message_template: Template, export_data: ExportData, date_str: str) -> None:
    output_messages_directory_name = os.path.join(OUTPUT_LOCATION, "messages_" + date_str)

    # We dump and reload the message data to/from JSON before rendering in order to make sure the template
    # will receive precisely the same type of objects (e.g. str instead of datetime) as the downstream tasks
    # that will work with the JSON and the templates. This allows us to catch some bugs earlier.
    export_data_dict = json.loads(json.dumps(dataclasses.asdict(export_data), cls=JSONEncoderAdditionalTypes))

    os.mkdir(output_messages_directory_name)
    for top_level_target in export_data_dict["messages"].keys():
        with open(os.path.join(output_messages_directory_name, top_level_target + ".html"), "w") as f:
            f.write(message_template.render({"data": export_data_dict["messages"][top_level_target]}))
    print()
    print(termcolor.colored(f"Messages written to: {output_messages_directory_name}", attrs=["bold"]))


def main(
    previous_reports_directory: Path = typer.Argument(
        None,
        help="The directory where JSON files from previous exports reside. This is to prevent the same (or similar) "
        "bug to be reported multiple times.",
    ),
    tag: Optional[str] = typer.Option(
        None,
        help="Allows you to filter by the tag you provided when adding targets to be scanned. Only vulnerabilities "
        "from targets with this tag will be exported.",
    ),
    language: Language = typer.Option(Language.en_US.value, help="Output report language (e.g. pl_PL or en_US)."),
    custom_template_arguments: str = typer.Option(
        "",
        help="Custom template arguments in the form of name1=value1,name2=value2,... - the original templates "
        "don't need them, but if you modified them on your side, they might.",
    ),
    blocklist_file: Optional[str] = typer.Option(
        None,
        help="Filter vulnerabilities from being included in the messages (this doesn't influence the scanning). "
        'Please refer to the "Generating e-mails" chapter of the web documentation '
        "for the syntax of the file.",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Print more information (e.g. whether some types of reports have not been observed for a long time).",
    ),
) -> None:
    blocklist = load_blocklist(blocklist_file)

    if previous_reports_directory:
        previous_reports = load_previous_reports(Path(HOST_ROOT_PATH) / str(previous_reports_directory).lstrip(os.sep))
    else:
        previous_reports = []

    custom_template_arguments_parsed = parse_custom_template_arguments(custom_template_arguments)
    db = DB()
    export_db_connector = DataLoader(db, blocklist, language, tag)
    export_data = build_export_data(previous_reports, tag, export_db_connector, custom_template_arguments_parsed)

    date_str = datetime.datetime.now().strftime("%Y-%m-%d_%H_%M_%S")
    _install_translations_and_print_path(language, date_str)
    _dump_export_data_and_print_path(export_data, date_str)
    message_template = _build_message_template_and_print_path(date_str)

    print_and_save_stats(export_data, date_str)

    if verbose:
        print_long_unseen_report_types(previous_reports + export_db_connector.reports)

        print("Available tags (and the counts of raw task results - not to be confused with vulnerabilities):")
        if None in export_db_connector.tag_stats:
            print(f"\tEmpty tag: {export_db_connector.tag_stats[None]}")  # type: ignore

        for tag in sorted([key for key in export_db_connector.tag_stats.keys() if key]):
            print(f"\t{tag}: {export_db_connector.tag_stats[tag]}")

    _build_messages_and_print_path(message_template, export_data, date_str)


if __name__ == "__main__":
    typer.run(main)
