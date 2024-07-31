#!/usr/bin/env python3
import dataclasses
import json
import os
import subprocess
from typing import Any, Dict, List

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url


@dataclasses.dataclass
class Message:
    category: str
    problems: List[str]

    @property
    def message(self) -> str:
        return f"{self.category}: {', '.join(self.problems)}"


def process_json_data(result: Dict[str, Any]) -> List[Message]:
    messages: Dict[str, Message] = {}

    # Iterate through key-value pairs in the result
    for key, value in result.items():
        # Split the key to extract the relevant part
        key_parts = key.replace("[", "").replace("]", "").split(". ")

        if key in [
            "[2. Fingerprint HTTP Response Headers]",
            "[3. Deprecated HTTP Response Headers/Protocols and Insecure Values]",
            "[4. Empty HTTP Response Headers Values]",
            "[5. Browser Compatibility for Enabled HTTP Security Headers]",
        ]:
            continue

        # Check if the key has the expected structure
        if len(key_parts) >= 2:
            category = key_parts[1].capitalize()

            # Check if the key is not in the excluded categories and there are relevant values
            if category.lower() != "info":
                # If the value is a dictionary, iterate through subkey-value pairs
                if isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        # Add subkeys and subvalues to messages
                        if subvalue and subvalue not in [
                            "Nothing to report, all seems OK!",
                            "No HTTP security headers are enabled.",
                        ]:
                            problem = f"{subkey} {subvalue}"
                            if category not in messages:
                                messages[category] = Message(category=category, problems=[])
                            messages[category].problems.append(problem)

                # If the value is a list, iterate through list items
                elif isinstance(value, list):
                    for item in value:
                        # Add list items to messages
                        if item and item not in [
                            "Nothing to report, all seems OK!",
                            "No HTTP security headers are enabled.",
                        ]:
                            if category not in messages:
                                messages[category] = Message(category=category, problems=[])
                            messages[category].problems.append(item)

    return list(messages.values())


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class Humble(ArtemisBase):
    """
    Runs humble -> A HTTP Headers Analyzer
    """

    identity = "humble"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        subprocess.call(["cp", "/humble/additional/user_agents.txt", "/humble/additional/user_agents.txt.bak"])

    def run(self, current_task: Task) -> None:
        if Config.Miscellaneous.CUSTOM_USER_AGENT:
            with open("/humble/additional/user_agents.txt", "w") as f:
                f.write(f"1.- {Config.Miscellaneous.CUSTOM_USER_AGENT}\n")
        else:
            # Reset back to the original content
            subprocess.call(["cp", "/humble/additional/user_agents.txt.bak", "/humble/additional/user_agents.txt"])

        base_url = get_target_url(current_task)

        data = subprocess.check_output(
            [
                "python3",
                "humble.py",
                "-u",
                base_url,
                "-b",
                "-o",
                "json",
            ],
            cwd="/humble",
            stderr=subprocess.DEVNULL,
        )

        # strip boilerplatetext from the output to get the location and filename of the output file
        filename = (
            data.decode("ascii", errors="ignore")
            .removeprefix("\n Analyzing URL and saving the report, please wait ...\n\n\n Report saved to ")
            .removesuffix("\n")
        )
        data_str = open(filename, "r").read()

        # cleanup file
        os.unlink(filename)

        # Check if the input string is empty
        if data_str.strip():
            result = json.loads(data_str)
        else:
            result = []

        # Parse the JSON data
        messages = process_json_data(result)

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
    Humble().loop()
