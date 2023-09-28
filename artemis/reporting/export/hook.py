from abc import ABC, abstractmethod
from pathlib import Path

from artemis.reporting.export.export_data import ExportData


class ExportHook(ABC):
    @staticmethod
    @abstractmethod
    def get_priority() -> int:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def run(output_dir: Path, export_data: ExportData) -> None:
        raise NotImplementedError()
