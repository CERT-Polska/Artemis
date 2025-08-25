import binascii
import itertools
import os
import random
import urllib.parse
from typing import IO, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup
from karton.core import Task
from pydantic import BaseModel

from artemis import http_requests, load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.config import Config
from artemis.module_base import ArtemisBase
from artemis.password_utils import get_passwords
from artemis.task_utils import get_target_url

COMMON_USERNAMES = ["admin"]


def read_file(file: IO[str]) -> List[str]:
    return [line.strip() for line in file if not line.startswith("#")]


with open(
    os.path.join(os.path.dirname(__file__), "data", "admin_panel_login_bruter", "common_failure_messages.txt")
) as f:
    COMMON_FAILURE_MESSAGES = read_file(f)

with open(os.path.join(os.path.dirname(__file__), "data", "admin_panel_login_bruter", "logout_messages.txt")) as f:
    LOGOUT_MESSAGES = read_file(f)

with open(os.path.join(os.path.dirname(__file__), "data", "admin_panel_login_bruter", "common_login_paths.txt")) as f:
    COMMON_LOGIN_PATHS = read_file(f)


class AdminPanelLoginBruterResult(BaseModel):
    url: str
    username: str
    password: str
    indicators: List[str]


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class AdminPanelLoginBruter(ArtemisBase):
    """
    Attempts to brute-force login pages of admin panels using common credentials.
    """

    num_retries = Config.Miscellaneous.SLOW_MODULE_NUM_RETRIES
    identity = "admin_panel_login_bruter"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def check_url(self, url: str) -> bool:
        """
        Checks if the given URL is accessible and returns a 200 status code.
        """
        try:
            response = http_requests.get(url)
            return response.status_code == 200 if response else False
        except requests.RequestException as e:
            self.log.debug(f"Error checking URL {url}: {e}")
            return False

    def discover_login_paths(self, base_url: str) -> List[str]:
        """
        Discovers common admin login paths by checking predefined URLs.
        """

        found_paths = []
        for path in COMMON_LOGIN_PATHS:
            full_url = urllib.parse.urljoin(base_url, path)
            if self.check_url(full_url):
                self.log.info("Discovered login path: %s", full_url)
                found_paths.append(path)
        return found_paths

    def brute_force_login_path(
        self, base_url: str, login_path: str, username: str, password: str
    ) -> Tuple[bool, Optional[AdminPanelLoginBruterResult]]:
        """
        Attempts to brute-force a login form at the given path using provided credentials.
        """
        self.log.info("Trying %s:%s on %s/%s", username, password, base_url, login_path.lstrip("/"))
        login_url = urllib.parse.urljoin(base_url, login_path)
        session = requests.session()
        login_form_found = False

        try:
            response = self.throttle_request(lambda: http_requests.request("get", login_url, session=session))
            if not response or response.status_code != 200:
                return (False, None)

            original_cookies = session.cookies.get_dict()  # type: ignore
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                action = form.get("action")
                form_url = urllib.parse.urljoin(login_url, action) if action else login_url
                inputs = form.find_all("input")

                form_data = {}
                found_username = False
                found_password = False

                for input_tag in inputs:
                    input_name = input_tag.get("name")
                    input_value = input_tag.get("value", "")
                    if input_name:
                        if (
                            "user" in input_name.lower()
                            or "name" in input_name.lower()
                            or "usr" in input_name.lower()
                            or "log" in input_name.lower()
                        ):
                            form_data[input_name] = username
                            found_username = True
                        elif "pass" in input_name.lower() or "pwd" in input_name.lower():
                            form_data[input_name] = password
                            found_password = True
                        else:
                            form_data[input_name] = input_value

                if not found_username or not found_password:
                    self.log.info("Didn't found username/pwd in form, ignoring...")
                    continue
                else:
                    self.log.info("Found username/pwd in form on %s, proceeding", login_url)
                    login_form_found = True

                try:
                    self.log.info("Post data: %s", form_data)
                    post_response = self.throttle_request(
                        lambda: http_requests.request(
                            "post",
                            form_url,
                            data=form_data,
                            session=session,
                        )
                    )
                except requests.RequestException as e:
                    self.log.debug(f"Error submitting to {form_url}: {e}")
                    continue

                if not post_response:
                    continue

                indicators = []

                new_cookies = session.cookies.get_dict()  # type: ignore
                if len(new_cookies) > len(original_cookies):
                    indicators.append("session_cookie")

                if any(logout_message.lower() in post_response.text.lower() for logout_message in LOGOUT_MESSAGES):
                    indicators.append("logout_link")

                failure_detected = any(
                    msg.lower() in post_response.text.lower() and msg.lower() not in response.text.lower()
                    for msg in COMMON_FAILURE_MESSAGES
                )
                if not failure_detected:
                    indicators.append("no_failure_messages")
                    login_success = True
                else:
                    login_success = False

                if login_success and indicators:
                    self.log.info(
                        "successful brute force form_url=%s username=%s password=%s", form_url, username, password
                    )
                    return (
                        True,
                        AdminPanelLoginBruterResult(
                            url=form_url,
                            username=username,
                            password=password,
                            indicators=indicators,
                        ),
                    )

        except Exception as e:
            self.log.warning(f"Error during brute force on {login_url}: {e}")

        return (login_form_found, None)

    def scan(self, task: Task, base_url: str, login_paths: List[str]) -> List[AdminPanelLoginBruterResult]:
        """
        Scans the target URL for vulnerable login paths using common credentials.
        """
        results = []
        credential_pairs = set()
        for path in login_paths:
            for username, password in itertools.product(COMMON_USERNAMES, get_passwords(task)):
                login_form_found, result = self.brute_force_login_path(base_url, path, username, password)
                if result:
                    self.log.info("Checking whether %s:%s indeed works", username, password)
                    rechecked = True
                    for _ in range(Config.Modules.AdminPanelLoginBruter.ADMIN_PANEL_LOGIN_BRUTER_NUM_RECHECKS):
                        _, result_good_password = self.brute_force_login_path(base_url, path, username, password)
                        # We also try the random password, to make sure we don't "log in" with that password - if we do, that is a false
                        # positive.
                        has_login_form_fake_password, result_fake_password = self.brute_force_login_path(
                            base_url,
                            path,
                            "this-username-should-not-exist",
                            binascii.hexlify(os.urandom(16)).decode("ascii"),
                        )

                        if not (result_good_password and has_login_form_fake_password and not result_fake_password):
                            rechecked = False
                            break

                    if rechecked:
                        results.append(result)
                        credential_pairs.add((username, password))
                        self.log.info("rechecked - works!")
                    else:
                        self.log.info("rechecked - doesn't work")

                if not login_form_found:  # not worth trying all other credential pairs
                    break

        if len(credential_pairs) > 1:
            # More than one successful working credential pair is most probably a FP. We do
            # accept working credentials on different paths though.
            results = []

        return results

    def run(self, current_task: Task) -> None:
        url = get_target_url(current_task)
        login_paths = self.discover_login_paths(url)
        random.shuffle(login_paths)

        results = self.scan(current_task, url, login_paths)

        if results:
            status = TaskStatus.INTERESTING
            status_reason = "Found weak credentials on admin panel(s): " + ", ".join(
                [f"{result.username}:{result.password} at {result.url}" for result in results]
            )
        else:
            status = TaskStatus.OK
            status_reason = None

        self.db.save_task_result(
            task=current_task,
            status=status,
            status_reason=status_reason,
            data={"results": [result.model_dump() for result in results]},
        )


if __name__ == "__main__":
    AdminPanelLoginBruter().loop()
