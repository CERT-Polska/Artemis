from abc import ABC, abstractmethod
from typing import Any, List

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
                data["services"][service][
                    "command"
                ] = "bash -c 'alembic upgrade head && uvicorn artemis.main:app --host 0.0.0.0 --port 5000 --reload'"
        return data


class VolumeDevelopStrategy(YamlProcessor):
    @staticmethod
    def create_list_of_services(data: Any) -> List[str]:
        services = data.get("services", {})
        karton_services = [name for name in services if name.startswith("karton") or name == "web"]

        return karton_services

    def process(self, data: Any) -> Any:
        services_to_create_volume = self.create_list_of_services(data)

        for service in data["services"]:
            if service in services_to_create_volume and "./:/opt" not in data["services"][service]["volumes"]:
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

    # We used to change "restart" to "no". We know, though, that some users use Artemis in development
    # version for actual scanning. Because the containers restart after a given number of scanning tasks,
    # that would prevent such users from scanning.
