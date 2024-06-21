from abc import ABC, abstractmethod
from typing import Any

import yaml


class YamlProcessor(ABC):
    @abstractmethod
    def process(self, data: Any) -> Any:
        pass


class LocalBuildStrategy(YamlProcessor):
    def process(self, data: Any) -> Any:
        if data["x-artemis-build-or-image"].get("image"):
            del data["x-artemis-build-or-image"]["image"]
            data["x-artemis-build-or-image"]["build"] = {"context": ".", "dockerfile": "docker/Dockerfile"}
            return data
        return data


class WebCommandStrategy(YamlProcessor):
    def process(self, data: Any) -> Any:
        for service in data["services"]:
            if service == "web":
                data["services"][service]["command"] = "uvicorn artemis.main:app --host 0.0.0.0 --port 5000 --reload"
        return data


class VolumeDevelopStrategy(YamlProcessor):
    def process(self, data: Any) -> Any:
        for service in data["services"]:
            if service == "web" and "./:/opt" not in data["services"][service]["volumes"]:
                data["services"][service]["volumes"].append("./:/opt")
        return data


class LocalBuildContainersStrategy(YamlProcessor):
    def process(self, data: Any) -> Any:
        for service in data["services"]:
            if data["services"][service]["image"] == "certpl/artemis:latest":
                del data["services"][service]["image"]
                data["services"][service]["build"] = {"context": ".", "dockerfile": "docker/Dockerfile"}
        return data


class FileProcessor:
    def __init__(self, input_file: str, output_file: str) -> None:
        self.docker_compose_data = None
        self.input_file = input_file
        self.output_file = output_file

    def set_data(self) -> None:
        self.docker_compose_data = yaml.safe_load(open(self.input_file))

    def process_file(self, strategy: YamlProcessor) -> None:
        self.docker_compose_data = strategy.process(self.docker_compose_data)

        with open(self.output_file, "w") as file:
            yaml.dump(self.docker_compose_data, file)


if __name__ == "__main__":

    input_yaml_file = "docker-compose.yaml"
    output_yaml_file = "docker-compose.dev.yaml"

    processor = FileProcessor(input_yaml_file, output_yaml_file)
    processor.set_data()

    processor.process_file(LocalBuildStrategy())

    processor.process_file(WebCommandStrategy())

    processor.process_file(VolumeDevelopStrategy())

    processor.process_file(LocalBuildContainersStrategy())
