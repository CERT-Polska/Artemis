import yaml
from abc import ABC, abstractmethod


class YamlProcessor(ABC):
    @abstractmethod
    def process(self, data):
        pass


class LocalBuildStrategy(YamlProcessor):
    def process(self, data):
        if data['x-artemis-build-or-image'].get('image'):
            del data['x-artemis-build-or-image']['image']
            data['x-artemis-build-or-image']['build'] = {
                'context': '.',
                'dockerfile': 'docker/Dockerfile'
            }
            return data
        return data


class WebCommandStrategy(YamlProcessor):
    def process(self, data):
        for service in data['services']:
            if service == 'web':
                data[
                    'services'
                ][service]['command'] = 'uvicorn artemis.main:app --host 0.0.0.0 --port 5000 --reload'
        return data


class VolumeDevelopStrategy(YamlProcessor):
    def process(self, data):
        for service in data['services']:
            if service == 'web' and './:/opt' not in data['services'][service]['volumes']:
                data['services'][service]['volumes'].append('./:/opt')
        return data


class LocalBuildContainersStrategy(YamlProcessor):
    def process(self, data):
        for service in data['services']:
            if data['services'][service]['image'] == 'certpl/artemis:latest':
                del data['services'][service]['image']
                data['services'][service]['build'] = {
                    'context': '.',
                    'dockerfile': 'docker/Dockerfile'
                }
        return data


class FileProcessor:
    def __init__(
            self,
            input_file: str,
            output_file: str,
            strategy: YamlProcessor = None
    ) -> None:
        self.docker_compose_data = None
        self._strategy = strategy
        self._input_file = input_file
        self._output_file = output_file

    @property
    def strategy(self) -> YamlProcessor:
        return self._strategy

    @property
    def input_file(self) -> str:
        return self._input_file

    @property
    def output_file(self) -> str:
        return self._output_file

    @strategy.setter
    def strategy(self, strategy: YamlProcessor) -> None:
        self._strategy = strategy

    @input_file.setter
    def input_file(self, input_file: str) -> None:
        self._input_file = input_file

    @output_file.setter
    def output_file(self, output_file: str) -> None:
        self._output_file = output_file

    def set_data(self) -> None:
        self.docker_compose_data = yaml.safe_load(open(self.input_file))

    def process_file(self) -> None:
        self.docker_compose_data = self.strategy.process(self.docker_compose_data)

        with open(self.output_file, 'w') as file:
            yaml.dump(self.docker_compose_data, file)


if __name__ == '__main__':

    input_yaml_file = "docker-compose.yaml"
    output_yaml_file = "docker-compose.temporary.yaml"

    processor = FileProcessor(input_yaml_file, output_yaml_file)
    processor.set_data()

    processor.strategy = LocalBuildStrategy()
    processor.process_file()

    processor.strategy = WebCommandStrategy()
    processor.process_file()

    processor.strategy = VolumeDevelopStrategy()
    processor.process_file()

    processor.strategy = LocalBuildContainersStrategy()
    processor.process_file()
