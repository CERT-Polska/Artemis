from abc import ABC, abstractmethod

from artemis.reporting.export.export_data import ExportData


class ExportHook(ABC):
    @staticmethod
    @abstractmethod
    def run(output_dir: str, export_data: ExportData) -> None:
        raise NotImplementedError()
