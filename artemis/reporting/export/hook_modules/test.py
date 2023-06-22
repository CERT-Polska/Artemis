from artemis.reporting.export.export_data import ExportData
from artemis.reporting.export.hook import ExportHook


class TestHook(ExportHook):
    @staticmethod
    def run(output_dir: str, export_data: ExportData) -> None:
        print(output_dir, export_data)
