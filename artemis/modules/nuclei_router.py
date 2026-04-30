#!/usr/bin/env python3
from typing import Any

from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url
from artemis.web_technology_identification import run_tech_detection

TECHNOLOGY_DETECTION_TAGS_TO_EXCLUDE = {"wordpress": "wordpress"}
# it's seperate with module configuration cause flags with values defined in router serve
# two purposes, configuration runtime for nuclei command and define grouping key to pickup tasks
NUCLEI_ROUTER_FLAGS_PAYLOAD_KEY = "nuclei-routing-additional-flags"


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class NucleiRouter(ArtemisBase):
    """
    Module in the middle to delegate nuclei tasks.
    """

    identity = "nuclei-router"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.known_techs_to_exclude = set(TECHNOLOGY_DETECTION_TAGS_TO_EXCLUDE.keys())

    def get_missing_tech(self, target: str) -> set[str]:
        technology_tags = run_tech_detection([target], self.log)

        detected_techs_set = {tech.lower() for tech in technology_tags.get(target, [])}
        known_detected_techs = set()
        for tech in self.known_techs_to_exclude:
            if any(tech in detected_tech for detected_tech in detected_techs_set):
                known_detected_techs.add(tech)

        return self.known_techs_to_exclude - known_detected_techs

    def get_tags_to_exclude(self, target: str) -> list[str]:
        undetected_techs = self.get_missing_tech(target)
        tags_to_exclude: set[str] = set()
        for tech_name in undetected_techs:
            tags_to_exclude.update(TECHNOLOGY_DETECTION_TAGS_TO_EXCLUDE[tech_name])
        return sorted(tags_to_exclude)

    def get_nuclei_additional_flags_for_task(self, target_url: str) -> list[str]:
        flags = []

        # Nuclei module implementation currently only supports '-etags'
        tags_to_exclude = self.get_tags_to_exclude(target_url)
        if tags_to_exclude:
            flags.extend(["-etags", ",".join(tags_to_exclude)])

        return flags

    def run(self, current_task: Task) -> None:
        target_url = get_target_url(current_task)

        nuclei_additional_flags = self.get_nuclei_additional_flags_for_task(target_url)
        routed_task = Task(
            {
                "type": TaskType.NUCLEI_TARGET,
            },
            payload={
                "url": target_url,
                NUCLEI_ROUTER_FLAGS_PAYLOAD_KEY: nuclei_additional_flags,
            },
        )
        self.add_task(current_task, routed_task)

        self.db.save_task_result(
            task=current_task,
            status=TaskStatus.OK,
            data={
                "routed_task_type": TaskType.NUCLEI_TARGET,
                "url": target_url,
                "nuclei_additional_flags": nuclei_additional_flags,
            },
        )


if __name__ == "__main__":
    NucleiRouter().loop()
