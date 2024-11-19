#!/usr/bin/env python3
import string
import urllib.parse

import bs4
import validators
from karton.core import Task
from publicsuffixlist import PublicSuffixList

from artemis import load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.resolvers import lookup
from artemis.task_utils import get_target_url
from artemis.utils import perform_whois_or_sleep

PUBLIC_SUFFIX_LIST = PublicSuffixList()


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.LOW)
class ScriptsUnregisteredDomains(ArtemisBase):
    """
    Checks, whether scripts are loaded from unregistered domains
    """

    identity = "scripts_unregistered_domains"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    # As the logic sometimes requires waiting 24 hours for the whois quota to be renewed, let's
    # set the timeout for 24 hours + 1 hour.
    timeout_seconds = (24 + 1) * 3600

    @staticmethod
    def _is_domain(domain: str) -> bool:
        # These are also domains
        if all(c in string.ascii_letters + "-" + string.digits for c in domain):
            return True

        try:
            # this validator returns either a VaildationError or a boolean
            return validators.domain(domain) is True
        except validators.ValidationFailure:
            return False

    def _is_domain_registered(self, domain: str) -> bool:
        try:
            ips = lookup(domain)
            if len(ips) > 0:
                return True

            nameservers = lookup(domain, "NS")
            if len(nameservers) > 0:
                return True
        except Exception as e:
            # Maybe doesn't exist, let's fallback for the next check
            self.log.info(f"Exception when trying to get IPs for {domain}: {e}")
            pass

        try:
            return perform_whois_or_sleep(domain, self.log) is not None
        except Exception as e:
            # When there is whois error, we treat the domain as unregistered - let's see whether
            # it doesn't cause too many false positives.
            self.log.error(f"Error in whois for {domain}: {e}")
            return False

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)

        content = self.http_get(url).content

        soup = bs4.BeautifulSoup(content, "html.parser")
        scripts = soup.find_all("script", src=True)
        scripts_from_unregistered_domains = []
        messages = []

        for script in scripts:
            src = script.get("src")
            url_parsed = urllib.parse.urlparse(src)

            if url_parsed.scheme in ["data", "chrome-extension"]:
                continue

            netloc = url_parsed.netloc.strip()

            if netloc and self._is_domain(netloc):
                privatesuffix = PUBLIC_SUFFIX_LIST.privatesuffix(netloc)

                if privatesuffix:
                    domain_to_check = privatesuffix
                else:
                    # if a domain is a public suffix
                    domain_to_check = netloc

                if self._is_domain_registered(domain_to_check):
                    self.log.info(f"Script on {netloc}, but {domain_to_check} is registered")
                else:
                    self.log.info(f"Script on {netloc} - {domain_to_check} unregistered!")
                    messages.append(f"{url} loads script from unregistered domain {netloc}")
                    scripts_from_unregistered_domains.append(
                        {"src": src, "domain": netloc, "privatesuffix": privatesuffix}
                    )

        if messages:
            status = TaskStatus.INTERESTING
            status_reason = ", ".join(messages)
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data=scripts_from_unregistered_domains,
        )


if __name__ == "__main__":
    ScriptsUnregisteredDomains().loop()
