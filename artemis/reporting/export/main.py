import copy
import dataclasses
import datetime
import json
import logging
import os
from pathlib import Path
from typing import Dict, Optional

import bs4
import termcolor
import typer
from jinja2 import BaseLoader, Environment, StrictUndefined, Template, select_autoescape

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
from artemis.utils import CONSOLE_LOG_HANDLER

environment = Environment(
    loader=BaseLoader(),
    extensions=["jinja2.ext.i18n"],
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    autoescape=select_autoescape(default=True),
)


def unwrap(html: str) -> str:
    """Uwraps html if it's wrapped in a single tag (e.g. <div>)."""
    html = html.strip()
    soup = bs4.BeautifulSoup(html)
    while len(list(soup.children)) == 1:
        only_child = list(soup.children)[0]

        if only_child.name:  # type: ignore
            only_child.unwrap()
            soup = bs4.BeautifulSoup(soup.renderContents().strip())
        else:
            break

    return soup.renderContents().decode("utf-8", "ignore")


def _build_message_template_and_print_path(output_dir: Path, silent: bool) -> Template:
    output_message_template_file_name = output_dir / "advanced" / "message_template.jinja2"

    message_template_content = build_message_template()
    message_template = environment.from_string(message_template_content)

    with open(output_message_template_file_name, "w") as f:
        f.write(message_template_content)

    if not silent:
        print(f"Message template written to file: {output_message_template_file_name}")
    return message_template


def _install_translations_and_print_path(language: Language, output_dir: Path, silent: bool) -> None:
    translations_file_name = output_dir / "advanced" / "translations.po"
    compiled_translations_file_name = output_dir / "advanced" / "compiled_translations.mo"
    install_translations(language, environment, translations_file_name, compiled_translations_file_name)

    if not silent:
        print(f"Translations written to file: {translations_file_name}")
        print(f"Compiled translations written to file: {compiled_translations_file_name}")


def _dump_export_data_and_print_path(export_data: ExportData, output_dir: Path, silent: bool) -> None:
    output_json_file_name = output_dir / "advanced" / "output.json"

    with open(output_json_file_name, "w") as f:
        json.dump(export_data, f, indent=4, cls=JSONEncoderAdditionalTypes)

    if not silent:
        print(f"JSON written to file: {output_json_file_name}")


def _build_messages_and_print_path(
    message_template: Template, export_data: ExportData, output_dir: Path, silent: bool
) -> None:
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

    for message in export_data.messages.values():
        for report in message.reports:
            message_data = {
                "contains_type": {report.report_type},
                "reports": [report],
                "custom_template_arguments": copy.deepcopy(message.custom_template_arguments),
            }
            message_data["custom_template_arguments"]["skip_html_and_body_tags"] = True  # type: ignore
            message_data["custom_template_arguments"]["skip_header_and_footer_text"] = True  # type: ignore
            report.html = unwrap(message_template.render({"data": message_data}))

    if not silent:
        print()
        print(termcolor.colored(f"Messages written to: {output_messages_directory_name}", attrs=["bold"]))


def export(
    language: Language,
    custom_template_arguments: Dict[str, str] = {},
    silent: bool = False,
    verbose: bool = False,
    previous_reports_directory: Optional[Path] = None,
    tag: Optional[str] = None,
    skip_hooks: bool = False,
    skip_suspicious_reports: bool = False,
) -> Path:
    if silent:
        CONSOLE_LOG_HANDLER.setLevel(level=logging.ERROR)
    blocklist = load_blocklist(Config.Miscellaneous.BLOCKLIST_FILE)

    if previous_reports_directory:
        previous_reports = load_previous_reports(previous_reports_directory)
    else:
        previous_reports = []

    db = DB()
    export_db_connector = DataLoader(db, blocklist, language, tag, silent)
    timestamp = datetime.datetime.now()
    export_data = build_export_data(
        previous_reports,
        tag,
        language,
        export_db_connector,
        custom_template_arguments,
        timestamp,
        skip_suspicious_reports,
    )
    date_str = timestamp.isoformat()
    output_dir = OUTPUT_LOCATION / str(tag) / date_str
    os.makedirs(output_dir)
    os.makedirs(output_dir / "advanced")

    _install_translations_and_print_path(language, output_dir, silent)

    if not skip_hooks:
        run_export_hooks(output_dir, export_data, silent)

    message_template = _build_message_template_and_print_path(output_dir, silent)
    _build_messages_and_print_path(message_template, export_data, output_dir, silent)
    _dump_export_data_and_print_path(export_data, output_dir, silent)

    print_and_save_stats(export_data, output_dir, silent)

    if silent:
        print(output_dir)

    if verbose and not silent:
        print_long_unseen_report_types(previous_reports + export_db_connector.reports)

        print("Available tags (and the counts of raw task results - not to be confused with vulnerabilities):")
        if None in export_db_connector.tag_stats:
            print(f"\tEmpty tag: {export_db_connector.tag_stats[None]}")  # type: ignore

        for tag in sorted([key for key in export_db_connector.tag_stats.keys() if key]):
            print(f"\t{tag}: {export_db_connector.tag_stats[tag]}")

    if not silent:
        for alert in export_data.alerts:
            print(termcolor.colored("ALERT:" + alert, color="red"))
    return output_dir


def export_cli(
    previous_reports_directory: Optional[Path] = typer.Argument(
        None,
        help="The directory where JSON files from previous exports reside. This is to prevent the same (or similar) "
        "bug to be reported multiple times.",
    ),
    tag: Optional[str] = typer.Option(
        None,
        help="Allows you to filter by the tag you provided when adding targets to be scanned. Only vulnerabilities "
        "from targets with this tag will be exported.",
    ),
    language: str = typer.Option(Language.en_US.value, help="Output report language (e.g. pl_PL or en_US)."),  # type: ignore
    custom_template_arguments: Optional[str] = typer.Option(
        "",
        help="Custom template arguments in the form of name1=value1,name2=value2,... - the original templates "
        "don't need them, but if you modified them on your side, they might.",
    ),
    silent: bool = typer.Option(
        False,
        "--silent",
        help="Print only the resulting folder path",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Print more information (e.g. whether some types of reports have not been observed for a long time).",
    ),
) -> Path:
    if custom_template_arguments is None:
        custom_template_arguments_parsed = {}
    else:
        custom_template_arguments_parsed = parse_custom_template_arguments(custom_template_arguments)
    return export(
        previous_reports_directory=previous_reports_directory,
        tag=tag,
        language=Language(language),
        custom_template_arguments=custom_template_arguments_parsed,
        silent=silent,
        verbose=verbose,
    )


if __name__ == "__main__":
    typer.run(export_cli)
