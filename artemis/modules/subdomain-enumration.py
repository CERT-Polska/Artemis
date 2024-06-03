#!/usr/bin/env python3
import urllib.parse
import re
import string
import time
from typing import Optional, Set
from bs4 import BeautifulSoup
import requests
from psycopg2 import OperationalError, connect

from karton.core import Task


from artemis.binds import TaskStatus, TaskType
from artemis.config import Config
from artemis.domains import is_subdomain
from artemis.module_base import ArtemisBase
from artemis.utils import check_output_log_on_error

DOMAIN_REGEX = r"([a-z0-9\-]+\.)+[a-z0-9\-]+"


class SubdomainEnumeration(ArtemisBase):
    """
    Consumes `type: domain` to gather subdomains and produces `type: domain`.
    """

    identity = "SubdomainEnumeration"
    filters = [
        {"type": TaskType.DOMAIN.value},
    ]
    # We don't ensure we're the only module touching the target, as actually we interact with the providers, not
    # the target. We lock the providers instead in the run() method.
    lock_target = False

    def get_subdomains_from_GAU(self, current_task: Task) -> None:
        domain = current_task.get_payload("domain")

        output = check_output_log_on_error(
            [
                "gau",
                "--subs",
            ]
            + Config.Modules.Gau.GAU_ADDITIONAL_OPTIONS,
            self.log,
            input=domain.encode("idna"),
        )

        domains = set()
        for line in output.decode("ascii", errors="ignore").splitlines():
            url_parsed = urllib.parse.urlparse(line)
            if not url_parsed.hostname:
                continue


        return domains

#rapid implementation

    def get_subdomains_from_rapid(self, current_task: Task) -> None:
        domain = current_task.get_payload("domain")
        try:
            response = requests.get(f"https://rapiddns.io/subdomain/{domain}#result")
        except requests.exceptions.RequestException:
            print("Unable to obtain information from rapiddns.io for domain %s", domain)
            return set()

        if response.ok:
            subdomains: Set[str] = set()
            soup = BeautifulSoup(response.text, 'html.parser')
            th_tags = soup.find_all('th')
            for th_tag in th_tags:
                td_tag = th_tag.find_next_sibling('td')
                if td_tag is not None:
                    url = td_tag.get_text()
                    subdomains.add(url)
            subdomains = set(subdomains)
        return subdomains

# jldc implementation
    def get_subdomains_from_jldc(self, current_task: Task) -> None:
        domain = current_task.get_payload("domain")
        try:
            subdomains: Set[str] = set()
            response = requests.get(f"https://jldc.me/anubis/subdomains/{domain}")
        except requests.exceptions.RequestException:
            print("Unable to obtain information from jldc.me for domain %s", domain)
        else:
            if response.ok:
                urls = eval(response.text)
                subdomains.update(urls)

        return subdomains

# crrtsh implementation
    def get_subdomains_from_crtsh(self, current_task: Task) -> None:
        #solves json query and gets the list
        try:
            response = requests.get(f"https://crt.sh/?q={domain}&output=json")
        except requests.exceptions.RequestException:
            self.log.exception("Unable to obtain information from crt.sh for domain %s", domain)
            return None

        if response.ok:
            subdomains: set[str] = set()
            for cert in response.json():
                for entry in cert["name_value"].split("\n"):
                    if re.fullmatch(DOMAIN_REGEX, entry):
                        subdomains.add(entry)
            return subdomains
        else:
            return None
#subfinder implementation
def get_subdomains_from_subfinder(self, current_task: Task) -> None:
    domain = current_task.get_payload("domain")
    try:
        subdomains: Set[str] = set()
        try:
            output = check_output_log_on_error(
                ["subfinder", 
                "-d", 
                domain, 
                "-all"],
                capture_output=True,
                text=True,
                check=True
            )
            subdomains.update(output.stdout.splitlines())
        except subprocess.CalledProcessError as e:
            self.log.exception("Unable to obtain information from subfinder for domain %s: %s", domain, e)

#amass implementation
    def get_subdomains_from_amass(self, current_task: Task) -> None:
        domain = current_task.get_payload("domain")
        try:
            subdomains: Set[str] = set()
            output = check_output_log_on_error(
                ["amass",
                "enum",
                "-passive",
                "-norecursive",
                "-noalts",
                "-d",
                domain],
                capture_output=True,
                text=True,
                check=True
            )
            subdomains.update(output.stdout.splitlines())
        except subprocess.CalledProcessError as e:
            self.log.exception("Unable to obtain information from amass for domain %s: %s", domain, e)

def run(self, current_task: Task) -> None:
    domains: Set[str] = set()
    domains = (
        get_subdomains_from_GAU() |
        get_subdomains_from_jldc()|
        get_subdomains_from_rapid()
        )

        def subdomain_check(subdomain):
                        if is_subdomain(url_parsed.hostname, domain):
                self.redis.setex(
                    f"gau-done-{domain}", Config.Miscellaneous.SUBDOMAIN_ENUMERATION_TTL_DAYS * 24 * 60 * 60, 1
                )
                domains.add(url_parsed.hostname)

    for retry_id in range(Config.Modules.Crtsh.CRTSH_NUM_RETRIES):

            if subdomains is None:
                subdomains = self.get_subdomains_from_crtsh(domain)

            if subdomains is None:
                self.log.info("crtsh: retrying for domain %s", domain)
                if retry_id < Config.Modules.Crtsh.CRTSH_NUM_RETRIES - 1:
                    time.sleep(Config.Modules.Crtsh.CRTSH_SLEEP_ON_RETRY_SECONDS)
                else:
                    raise UnableToObtainSubdomainsException()
            else:
                break

    for domain in domains:
            task = Task(
                {"type": TaskType.DOMAIN},
                payload={
                    "domain": domain,
                },
            )
            self.add_task(current_task, task)