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

    def run(self, current_task: Task) -> None:
        base_url = get_target_url(current_task)
        self.log.info(f"Starting moodlescan for {base_url}")

        try:
            # Run moodlescan with error output captured
            process = subprocess.run(
                [
                    "python3",
                    "moodlescan.py",
                    "-u",
                    base_url,
                    "-r",
                    "-k"
                ],
                cwd="/moodle_scanner",
                capture_output=True,
                text=True,
                check=True
            )
            
            self.log.info(f"Moodlescan stdout: {process.stdout}")
            if process.stderr:
                self.log.warning(f"Moodlescan stderr: {process.stderr}")

            # Parse the output for relevant information
            output_lines = process.stdout.splitlines()
            server_info = None
            version_info = None
            vulnerabilities = []

            for i, line in enumerate(output_lines):
                if "Error: Can't connect" in line:
                    self.log.info(f"Connection error: {line}")
                    self.db.save_task_result(
                        task=current_task,
                        status=TaskStatus.OK,
                        status_reason=line,
                        data={"raw_output": process.stdout}
                    )
                    return
                    
                if "server" in line.lower() and ":" in line:
                    server_info = line.split(":", 1)[1].strip()
                elif "version" in line.lower() and not line.startswith("."):
                    # Look at next line for version info if it's not dots or error
                    if i + 1 < len(output_lines):
                        next_line = output_lines[i + 1].strip()
                        if next_line and not next_line.startswith(".") and "error" not in next_line.lower():
                            version_info = next_line
                elif "vulnerability" in line.lower() or "cve" in line.lower():
                    vulnerabilities.append(line.strip())

            result = {
                "server": server_info,
                "version": version_info,
                "vulnerabilities": vulnerabilities,
                "raw_output": process.stdout
            }

            # Determine if anything interesting was found
            if vulnerabilities:
                status = TaskStatus.INTERESTING
                status_reason = f"Found: {', '.join(vulnerabilities)}"
            elif version_info and version_info != "Version not found":
                status = TaskStatus.INTERESTING
                status_reason = f"Found version: {version_info}"
            else:
                status = TaskStatus.OK
                status_reason = "Version not found" if version_info == "Version not found" else None

            self.db.save_task_result(
                task=current_task,
                status=status,
                status_reason=status_reason,
                data=result
            )

        except subprocess.CalledProcessError as e:
            self.log.error(f"Failed to run moodlescan for {base_url}")
            self.log.error(f"Exit code: {e.returncode}")
            self.log.error(f"Stdout: {e.stdout}")
            self.log.error(f"Stderr: {e.stderr}")
            self.db.save_task_result(
                task=current_task,
                status=TaskStatus.ERROR,
                status_reason=f"Failed to execute moodlescan: {e.stderr}",
                data={"stdout": e.stdout, "stderr": e.stderr},
            )
            return


if __name__ == "__main__":
    MoodleScanner().loop()
