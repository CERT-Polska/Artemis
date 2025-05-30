#!/usr/bin/env python3
from typing import Any, Dict

from artemis.modules.base.module_runtime_configuration import ModuleRuntimeConfiguration


class MailDNSScannerConfiguration(ModuleRuntimeConfiguration):
    def __init__(
        self,
        report_warnings: bool = False,
    ) -> None:
        super().__init__()
        self.report_warnings = report_warnings

    def serialize(self) -> Dict[str, Any]:
        result = super().serialize()
        result.update({"report_warnings": self.report_warnings})
        return result

    @classmethod
    def deserialize(cls, config_dict: Dict[str, Any]) -> "MailDNSScannerConfiguration":
        report_warnings = config_dict.get("report_warnings", False)

        return cls(
            report_warnings=report_warnings,
        )
