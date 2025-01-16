#!/usr/bin/env python3
import dataclasses
import json
import os
import subprocess
from typing import Any, Dict, List, Optional

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url


@dataclasses.dataclass
class MoodleMessage:
    category: str
    problems: List[str]

    @property
    def message(self) -> str:
        return f"{self.category}: {', '.join(self.problems)}"


def process_moodle_json(result: Dict[str, Any]) -> List[MoodleMessage]:
    messages: Dict[str, MoodleMessage] = {}

    for key, value in result.items():
        key_parts = key.replace("[", "").replace("]", "").split(". ")

        if key in [
            "[2. Moodle Security Checks]",
            "[3. Deprecated Moodle Versions]",
        ]:
            continue

        if len(key_parts) >= 2:
            category = key_parts[1].capitalize()

            if category.lower() != "info":
                if isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        if subvalue and subvalue not in [
                            "Nothing to report, all seems OK!",
                        ]:
                            problem = f"{subkey} {subvalue}"
                            if category not in messages:
                                messages[category] = MoodleMessage(category=category, problems=[])
                            messages[category].problems.append(problem)
                elif isinstance(value, list):
                    for item in value:
                        if item and item not in [
                            "Nothing to report, all seems OK!",
                        ]:
                            if category not in messages:
                                messages[category] = MoodleMessage(category=category, problems=[])
                            messages[category].problems.append(item)

    return list(messages.values())


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class MoodleScanner(ArtemisBase):
    """
    Runs Moodle-Scanner -> A Moodle Vulnerability Analyzer
    """

    identity = "moodle_scanner"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Backup existing Moodle-Scanner user agents if any
        subprocess.call(["cp", "/moodle_scanner/config/user_agents.txt", "/moodle_scanner/config/user_agents.txt.bak"])

    def run(self, current_task: Task) -> None:
        base_url = get_target_url(current_task)

        try:
            data = subprocess.check_output(
                [
                    "python3",
                    "scanner.py",
                    "-u",
                    base_url,
                    "--output",
                    "json",
                    "-r"
                ],
                cwd="/moodle_scanner",
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            self.log.error(f"Failed to run Moodle-Scanner for {base_url}")
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason="Failed to execute Moodle-Scanner",
                data={},
            )
            return

        # Extract filename from the output
        output_prefix = "\n Running Moodle-Scanner and saving the report...\n\n Report saved to "
        decoded_data = data.decode("ascii", errors="ignore")
        if output_prefix in decoded_data:
            filename = decoded_data.split(output_prefix)[-1].strip()
        else:
            self.log.error(f"Unexpected Moodle-Scanner output format for {base_url}")
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason="Unexpected Moodle-Scanner output format",
                data={},
            )
            return

        try:
            with open(filename, "r") as f:
                data_str = f.read()
        except FileNotFoundError:
            self.log.error(f"Report file {filename} not found for {base_url}")
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason="Report file not found",
                data={},
            )
            return

        # Cleanup
        os.unlink(filename)

        if data_str.strip():
            try:
                result = json.loads(data_str)
            except json.JSONDecodeError:
                self.log.error(f"Invalid JSON format in report for {base_url}")
                self.db.save_task_result(
                    task=current_task,
                    status=TaskStatus.ERROR,
                    status_reason="Invalid JSON format in report",
                    data={},
                )
                return
        else:
            result = {}

        # Parse the JSON data
        messages = process_moodle_json(result)

        if messages:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join([message.message for message in messages])
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={
                "original_result": result,
                "message_data": [dataclasses.asdict(message) for message in messages],
                "messages": [message.message for message in messages],
            },
        )


if __name__ == "__main__":
    MoodleScanner().loop()
