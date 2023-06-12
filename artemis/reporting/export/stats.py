import os

from artemis.reporting.export.common import OUTPUT_LOCATION
from artemis.reporting.export.export_data import ExportData


def print_and_save_stats(export_data: ExportData, date_str: str) -> None:
    output_stats_file_name = os.path.join(OUTPUT_LOCATION, "stats_" + date_str + ".txt")

    with open(output_stats_file_name, "w") as f:
        f.write(f"Reports total: {sum([len(item.reports) for item in export_data.messages.values()])}\n")

        for count, report_type in reversed(
            sorted([(count, report_type) for report_type, count in export_data.num_reports_per_type.items()])
        ):
            f.write(f"Num reports of type {report_type}: {count}\n")
    print(f"Stats (written to file: {output_stats_file_name}):")
    with open(output_stats_file_name, "r") as f:
        for line in f:
            print("\t" + line.strip())
