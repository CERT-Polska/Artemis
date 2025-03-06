from enum import Enum
from typing import Any, Dict, List

import xray
from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url


class PDFScannerFindings(Enum):
    CENSORSHIP_WEAKNESS = "censorship_weakness"


class PDFCensorScanner(ArtemisBase):
    """Scans PDFs for censorships using x-ray"""

    identity = "pdf_censor_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def process(self, url) -> Dict[int, List[Dict[str, Any]]]:
        pdf = self.http_get(url).content
        detected_text = xray.inspect(pdf)
        return detected_text

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        if url.endswith(".pdf"):
            self.log.info(f"PDF Censorship Scanner Scanning:{url}")
        else:
            self.log.error(f"{url} is not a valid PDF file")

        detected_text = self.process(url)

        self.db.save_task_result(
            task=current_task,
            data={"detected_text": detected_text},
        )


if __name__ == "__main__":
    PDFCensorScanner().loop()
