from collections import Counter
from pathlib import Path

from artemis.reporting.base.report_type import ReportType
from artemis.reporting.export.export_data import ExportData


def print_and_save_stats(export_data: ExportData, output_dir: Path, silent: bool) -> None:
    num_reports_per_type: Counter[ReportType] = Counter()

    for _, data in export_data.messages.items():
        num_reports_per_type.update([report.report_type for report in data.reports])

    output_stats_file_name = output_dir / "stats.txt"

    with open(output_stats_file_name, "w") as f:
        f.write(f"Reports total: {sum([len(item.reports) for item in export_data.messages.values()])}\n")

        for count, report_type in reversed(
            sorted([(count, report_type) for report_type, count in num_reports_per_type.items()])
        ):
            f.write(f"Number of reports of type {report_type}: {count}\n")

    if not silent:
        print(f"Stats (written to file: {output_stats_file_name}):")
        with open(output_stats_file_name, "r") as f:
            for line in f:
                print("\t" + line.strip())
