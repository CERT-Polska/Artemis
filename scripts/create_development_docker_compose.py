import argparse
from abc import ABC, abstractmethod
from typing import Any, List

import yaml


class YamlProcessor(ABC):
    @abstractmethod
    def process(self, data: Any) -> Any:
        pass


class LocalBuildStrategy(YamlProcessor):
    def process(self, data: Any) -> Any:

        for service in data["services"]:
            data["services"][service]["stdin_open"] = True
            data["services"][service]["tty"] = True

        if data.get("x-artemis-build-or-image") and data["x-artemis-build-or-image"].get("image"):
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
            if data["services"][service].get("image") == "certpl/artemis:latest":
                del data["services"][service]["image"]
                data["services"][service]["build"] = {"context": ".", "dockerfile": "docker/Dockerfile"}
        return data


class PostgresOpenPortsStrategy(YamlProcessor):
    def process(self, data: Any) -> Any:
        for service in data["services"]:
            if service == "postgres":
                data["services"][service]["ports"] = ["5432:5432"]
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

    parser = argparse.ArgumentParser(
        description="Transform docker-compose files to development versions",
    )

    parser.add_argument(
        "-i",
        "--input",
        nargs="+",
        required=False,
        default=["docker-compose.yaml"],
        help="Input docker-compose YAML files",
    )

    args = parser.parse_args()

    for input_file in args.input:

        index = input_file.rfind(".")
        extension = input_file[index + 1 :]
        output_file = f"{input_file[:index]}.dev.{extension}"

        processor = FileProcessor(
            input_file=input_file,
            output_file=output_file,
        )

        processor.set_data()

        processor.process_file(LocalBuildStrategy())

        processor.process_file(WebCommandStrategy())

        if input_file == "docker-compose.yaml":

            processor.process_file(VolumeDevelopStrategy())

            processor.process_file(LocalBuildContainersStrategy())

        processor.process_file(PostgresOpenPortsStrategy())

    # We used to change "restart" to "no". We know, though, that some users use Artemis in development
    # version for actual scanning. Because the containers restart after a given number of scanning tasks,
    # that would prevent such users from scanning.
