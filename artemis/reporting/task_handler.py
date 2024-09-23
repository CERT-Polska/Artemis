import hashlib
import json
import shutil
import tempfile
import time
import traceback
from pathlib import Path

from artemis import utils
from artemis.db import DB, ReportGenerationTask, ReportGenerationTaskStatus
from artemis.reporting.base.language import Language
from artemis.reporting.export.main import export

db = DB()
logger = utils.build_logger(__name__)


def handle_single_task(report_generation_task: ReportGenerationTask) -> Path:
    if report_generation_task.skip_previously_exported:
        previous_reports_directory = tempfile.mkdtemp()
        # We want to treat only the reports visible from web as already known
        for report_generation_task in db.list_report_generation_tasks():
            if report_generation_task.output_location:
                shutil.copy(
                    Path(report_generation_task.output_location) / "advanced" / "output.json",
                    Path(previous_reports_directory)
                    / (hashlib.sha256(report_generation_task.output_location.encode("ascii")).hexdigest() + ".json"),
                )
    else:
        previous_reports_directory = None

    try:
        return export(
            previous_reports_directory=Path(previous_reports_directory) if previous_reports_directory else None,
            tag=report_generation_task.tag,
            language=Language(report_generation_task.language),
            custom_template_arguments=report_generation_task.custom_template_arguments or {},  # type: ignore
            silent=True,
            skip_hooks=report_generation_task.skip_hooks,
        )
    finally:
        if previous_reports_directory:
            shutil.rmtree(previous_reports_directory)


def main() -> None:
    while True:
        task = db.take_single_report_generation_task()

        if task:
            logger.info(
                "Took reporting task: skip_previously_exported=%s tag=%s language=%s custom_template_arguments=%s",
                task.skip_previously_exported,
                task.tag,
                task.language,
                task.custom_template_arguments,
            )
            try:
                output_location = handle_single_task(task)
                with open(output_location / "advanced" / "output.json") as output_file:
                    output_data = json.load(output_file)
                    alerts = output_data["alerts"]

                db.save_report_generation_task_results(
                    task, ReportGenerationTaskStatus.DONE, output_location=str(output_location), alerts=alerts
                )
                logger.info("Reporting task succeeded")
            except Exception:
                logger.exception("Reporting task failed")
                db.save_report_generation_task_results(
                    task, ReportGenerationTaskStatus.FAILED, error=traceback.format_exc()
                )

        time.sleep(1)


if __name__ == "__main__":
    main()
