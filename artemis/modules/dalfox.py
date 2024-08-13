#!/usr/bin/env python3
import json
import os
import random
import shutil
import subprocess
import urllib
from typing import Any, Dict, List

import more_itertools
from karton.core import Task

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.crawling import get_links_and_resources_on_same_domain
from artemis.karton_utils import check_connection_to_base_url_and_save_error
from artemis.module_base import ArtemisBase
from artemis.task_utils import get_target_url
from artemis.utils import check_output_log_on_error
from artemis.task_utils import get_target_url


class DalFox(ArtemisBase):
    """
    Runs Nuclei templates on URLs.
    """

    identity = "dalfox"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

    def run(self, current_task):
        # url = get_target_url(current_task)
        url = "http://172.18.0.10:80/xss.php?name=annla"
        try:
            command = f'dalfox url {url}  --format json > output_{url.replace("://", "_").replace("/", "_")}.json'
            subprocess.run(command, shell=True, check=True)

            print(
                f"Skanowanie linka {url} zakończone.")
        except subprocess.CalledProcessError as e:
            print(f"Błąd podczas uruchamiania DalFox: {e}")

        self.analyze_results(url)

    @staticmethod
    def analyze_results(url):
        # try:
        with open(f'output_{url.replace("://", "_").replace("/", "_")}.json', 'r') as json_file:
            results = json.load(json_file)

        vulnerabilities = []
        for result in results:
            if 'param' in result and 'payload' in result:
                vulnerability = {
                    'param': result['param'],
                    'payload': result['payload']
                }
                vulnerabilities.append(vulnerability)

        print("--->", vulnerabilities)

        with open(f'vulnerabilities_{url.replace("://", "_").replace("/", "_")}.json', 'w') as json_output:
            json.dump(vulnerabilities, json_output, indent=2)

        print(
            f"Podatne parametry i POC zapisane w pliku vulnerabilities_{url.replace('://', '_').replace('/', '_')}.json.")

        # except Exception as e:
        #     print(f"Błąd podczas analizy wyników: {e}")


if __name__ == "__main__":
    DalFox().loop()
