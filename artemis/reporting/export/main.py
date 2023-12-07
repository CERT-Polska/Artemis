import dataclasses
import datetime
import json
import os
from pathlib import Path
from typing import Optional

import termcolor
import typer
from jinja2 import BaseLoader, Environment, StrictUndefined, Template

from artemis.blocklist import load_blocklist
from artemis.config import Config
from artemis.db import DB
from artemis.json_utils import JSONEncoderAdditionalTypes
from artemis.reporting.base.language import Language
from artemis.reporting.base.templating import build_message_template
from artemis.reporting.export.common import OUTPUT_LOCATION
from artemis.reporting.export.custom_template_arguments import (
    parse_custom_template_arguments,
)
from artemis.reporting.export.db import DataLoader
from artemis.reporting.export.export_data import ExportData, build_export_data
from artemis.reporting.export.hooks import run_export_hooks
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


def _build_message_template_and_print_path(output_dir: Path) -> Template:
    output_message_template_file_name = output_dir / "message_template.jinja2"

    message_template_content = build_message_template()
    message_template = environment.from_string(message_template_content)

    with open(output_message_template_file_name, "w") as f:
        f.write(message_template_content)

    print(f"Message template written to file: {output_message_template_file_name}")
    return message_template


def _install_translations_and_print_path(language: Language, output_dir: Path) -> None:
    translations_file_name = output_dir / "translations.po"
    compiled_translations_file_name = output_dir / "compiled_translations.mo"
    install_translations(language, environment, translations_file_name, compiled_translations_file_name)

    print(f"Translations written to file: {translations_file_name}")
    print(f"Compiled translations written to file: {compiled_translations_file_name}")


def _dump_export_data_and_print_path(export_data: ExportData, output_dir: Path) -> None:
    output_json_file_name = output_dir / "output.json"

    with open(output_json_file_name, "w") as f:
        json.dump(export_data, f, indent=4, cls=JSONEncoderAdditionalTypes)

    print(f"JSON written to file: {output_json_file_name}")


def _build_messages_and_print_path(message_template: Template, export_data: ExportData, output_dir: Path) -> None:
    output_messages_directory_name = output_dir / "messages"

    # We dump and reload the message data to/from JSON before rendering in order to make sure the template
    # will receive precisely the same type of objects (e.g. str instead of datetime) as the downstream tasks
    # that will work with the JSON and the templates. This allows us to catch some bugs earlier.
    export_data_dict = json.loads(json.dumps(dataclasses.asdict(export_data), cls=JSONEncoderAdditionalTypes))

    os.mkdir(output_messages_directory_name)
    for top_level_target in export_data_dict["messages"].keys():
        max_length = os.pathconf("/", "PC_NAME_MAX") - (len("...") + len(".html"))
        if len(top_level_target) >= max_length:
            top_level_target_shortened = top_level_target[:max_length] + "..."
        else:
            top_level_target_shortened = top_level_target

        with open(output_messages_directory_name / (top_level_target_shortened + ".html"), "w") as f:
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
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Print more information (e.g. whether some types of reports have not been observed for a long time).",
    ),
) -> None:
    blocklist = load_blocklist(Config.Miscellaneous.BLOCKLIST_FILE)

    if previous_reports_directory:
        previous_reports = load_previous_reports(Path(HOST_ROOT_PATH) / str(previous_reports_directory).lstrip(os.sep))
    else:
        previous_reports = []

    custom_template_arguments_parsed = parse_custom_template_arguments(custom_template_arguments)
    db = DB()
    export_db_connector = DataLoader(db, blocklist, language, tag)
    # we strip microseconds so that the timestamp in export_data json and folder name are equal
    timestamp = datetime.datetime.now().replace(microsecond=0)
    export_data = build_export_data(
        previous_reports, tag, export_db_connector, custom_template_arguments_parsed, timestamp
    )
    date_str = timestamp.strftime("%Y-%m-%d_%H_%M_%S")
    output_dir = OUTPUT_LOCATION / date_str
    os.mkdir(output_dir)

    _install_translations_and_print_path(language, output_dir)

    run_export_hooks(output_dir, export_data)

    _dump_export_data_and_print_path(export_data, output_dir)
    message_template = _build_message_template_and_print_path(output_dir)

    print_and_save_stats(export_data, output_dir)

    if verbose:
        print_long_unseen_report_types(previous_reports + export_db_connector.reports)

        print("Available tags (and the counts of raw task results - not to be confused with vulnerabilities):")
        if None in export_db_connector.tag_stats:
            print(f"\tEmpty tag: {export_db_connector.tag_stats[None]}")  # type: ignore

        for tag in sorted([key for key in export_db_connector.tag_stats.keys() if key]):
            print(f"\t{tag}: {export_db_connector.tag_stats[tag]}")

    _build_messages_and_print_path(message_template, export_data, output_dir)

    for alert in export_data.alerts:
        print(termcolor.colored("ALERT:" + alert, color="red"))


if __name__ == "__main__":
    typer.run(main)
