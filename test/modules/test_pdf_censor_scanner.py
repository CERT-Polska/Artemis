from test.base import ArtemisModuleTestCase
from unittest.mock import Mock, patch

from karton.core import Task

from artemis.binds import Service, TaskType
from artemis.modules.pdf_censor_scanner import PDFCensorScanner


class TestPDFCensorScanner(ArtemisModuleTestCase):
    karton_class = PDFCensorScanner

    def test_simple(self) -> None:
        pdf_url = "file:///home/zeit/Downloads/rectangles_yes_2.pdf"

        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            data={"detected_text": {1: [{"bbox": (105.4800033569336, 75.0, 119.63999938964844, 87.0), "text": "def"}]}},
        )

        result = self.run_task(task)
        print(result)
