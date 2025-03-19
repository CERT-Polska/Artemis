import binascii
import json
import os
import time
from difflib import SequenceMatcher
from typing import Set

import requests
from karton.core import Task
from urllib3.util import connection

from artemis import http_requests, load_risk_class
from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.utils import build_logger

_orig_create_connection = connection.create_connection


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class RemovedDomainExistingVhost(ArtemisBase):
    """
    A module that checks that despite removing domain, the corresponding vhost still exists on the server.
    """

    identity = "removed_domain_existing_vhost"
    filters = [{"type": TaskType.DOMAIN_THAT_MAY_NOT_EXIST.value}]

    def _obtain_past_target_ips(self, domain: str) -> Set[str]:
        result: Set[str] = set()
        for url in Config.Modules.RemovedDomainExistingVhost.REMOVED_DOMAIN_EXISTING_VHOST_PASSIVEDNS_URLS:
            time.sleep(
                Config.Modules.RemovedDomainExistingVhost.REMOVED_DOMAIN_EXISTING_VHOST_PASSIVEDNS_SLEEP_BETWEEN_REQUESTS_SECONDS
            )
            response = http_requests.get(url + domain)
            self.log.info(
                "Response for '%s': status code=%s, first bytes: %s",
                domain,
                response.status_code,
                response.content[:30],
            )
            if response.status_code == 404:
                continue

            data = response.content
            for line in data.split("\n"):
                if not line:
                    continue

                try:
                    item = json.loads(line)
                except json.decoder.JSONDecodeError:
                    self.log.error("Unable to parse response: %s", line)
                    continue

                if item["rrtype"] in ["A", "AAAA"]:
                    result.add(item["rrname"])

        return result

    @staticmethod
    def _request_with_patched_ip(url: str, patch_domain: str, patch_ip_to: str) -> http_requests.HTTPResponse:
        def patched_create_connection(address, *args, **kwargs):  # type: ignore
            host, port = address
            if host == patch_domain:
                host = patch_ip_to
            return _orig_create_connection((host, port), *args, **kwargs)  # type: ignore

        connection.create_connection = patched_create_connection

        try:
            return http_requests.get(url)
        finally:
            connection.create_connection = _orig_create_connection

    def run(self, current_task: Task) -> None:
        domain = current_task.get_payload("domain")

        if self.check_domain_exists(domain):
            self.db.save_task_result(task=current_task, status=TaskStatus.OK, status_reason="Domain exists")
            return

        target_ips = self._obtain_past_target_ips(domain)
        if not target_ips:
            self.db.save_task_result(
                task=current_task, status=TaskStatus.OK, status_reason="Unable to obtain past target ips"
            )
            return

        prefix = binascii.hexlify(os.urandom(3)).decode("ascii")
        for ip in target_ips:
            for proto in ["http", "https"]:
                try:
                    response_for_old_domain = self._request_with_patched_ip(proto + "://" + domain, domain, ip)
                    response_for_other_vhost = self._request_with_patched_ip(
                        proto + "://" + prefix + domain, prefix + domain, ip
                    )
                except requests.exceptions.RequestException:
                    self.log.exception("Unable to download website content")
                    continue

                try:
                    parent_domain = ".".join(domain.split(".")[1:])
                    response_for_parent_domain = self._request_with_patched_ip(
                        proto + "://" + parent_domain, parent_domain, ip
                    )

                    ratio = SequenceMatcher(
                        None, response_for_old_domain.content, response_for_parent_domain.content
                    ).quick_ratio()
                    if (
                        ratio
                        > Config.Modules.RemovedDomainExistingVhost.REMOVED_DOMAIN_EXISTING_VHOST_SIMILARITY_THRESHOLD
                    ):
                        self.log.info(
                            f"Domain {domain} has similar content to parent {parent_domain} (ratio={ratio}), nothing interesting, skipping..."
                        )
                        continue
                    else:
                        self.log.info(
                            f"Domain {domain} has not similar content to parent {parent_domain} (ratio={ratio})"
                        )
                except requests.exceptions.RequestException:
                    self.log.exception("Unable to download parent website content")

                ratio = SequenceMatcher(
                    None, response_for_old_domain.content, response_for_other_vhost.content
                ).quick_ratio()
                self.log.info(
                    f"Similarity between correct and incorrect domain is {ratio} nd status code is {response_for_old_domain.status_code}"
                )

                if (
                    response_for_old_domain.status_code in range(200, 300)
                    and ratio
                    < Config.Modules.RemovedDomainExistingVhost.REMOVED_DOMAIN_EXISTING_VHOST_SIMILARITY_THRESHOLD
                ):
                    self.db.save_task_result(
                        task=current_task,
                        status=TaskStatus.INTERESTING,
                        status_reason=f"Detected that {ip} hosts nonexistent domain {domain}",
                        data={
                            "ip": ip,
                            "domain": domain,
                            "response_for_old_domain": response_for_old_domain.content,
                            "response_for_other_vhost": response_for_other_vhost.content,
                            "similarity": ratio,
                        },
                    )
                    return
        self.db.save_task_result(
            task=current_task,
            status=TaskStatus.OK,
            status_reason=f"Didn't detect that any of ips: {target_ips} host {domain}",
        )


if __name__ == "__main__":
    if Config.Modules.RemovedDomainExistingVhost.REMOVED_DOMAIN_EXISTING_VHOST_PASSIVEDNS_URLS:
        RemovedDomainExistingVhost().loop()
    else:
        no_pdns_config_message_printed_filename = "/.no-pdns-config-message-shown"

        if not os.path.exists(no_pdns_config_message_printed_filename):
            # We want to display the message only once
            LOGGER = build_logger(__name__)
            LOGGER.error(
                "PassiveDNS config is required to start the module that detects cases where a server still hosts a domain that doesn't exist anymore."
            )
            LOGGER.error("Don't worry - all other modules can be used.")

            with open(no_pdns_config_message_printed_filename, "w"):
                pass
