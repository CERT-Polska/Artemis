from abc import ABC, abstractmethod
from pathlib import Path

from artemis.reporting.export.export_data import ExportData


class ExportHook(ABC):
    @staticmethod
    @abstractmethod
    def get_ordering() -> int:
        """The lower the order, the earlier it will run if multiple hooks are present."""
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def run(output_dir: Path, export_data: ExportData, silent: bool) -> None:
        raise NotImplementedError()
