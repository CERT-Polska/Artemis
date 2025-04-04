import binascii
import logging
import os
import random
import urllib.parse
from typing import List, Optional

import requests
from bs4 import BeautifulSoup
from karton.core import Task
from pydantic import BaseModel

from artemis import http_requests, load_risk_class
from artemis.binds import Service, TaskStatus, TaskType
from artemis.module_base import ArtemisBase
from artemis.password_utils import get_passwords
from artemis.task_utils import get_target_url

COMMON_USERNAMES = ["admin"]

COMMON_FAILURE_MESSAGES = [
    "Please enter the correct username and password for a staff account",  # Django
    "Username of password do not match or you do not have an account yet",  # Joomla
    "Login failed.",  # PhppgAdmin
    # Common phrases that occur in failed login attempts - don't put single words here,
    # as that may lead to false positives
    "access denied",
    "not permitted",
    "not authorized",
    "not authenticated",
    "not logged in",
    "Note that both fields may be case-sensitive.",
    "Unrecognized username or password. Forgot your password?",
    "Invalid credentials",
    "The login is invalid",
    "not seem to be correct",
    "Access denied",
    "Cannot log in",
    "login details do not seem to be correct",
    # rate limit
    "failed login attempts for this account",
    # pl_PL
    "Podano błędne dane logowania",
    "Wprowadź poprawne dane",
    "Nieprawidłowa nazwa użytkownika lub hasło",
    "Nazwa użytkownika lub hasło nie jest",
    "Złe hasło",
    "niepoprawne hasło",
    "Błędna nazwa użytkownika",
]


LOGOUT_MESSAGES = [
    "logout",
    "sign out",
    "wyloguj",
]


class AdminPanelLoginBruterResult(BaseModel):
    url: str
    username: str
    password: str
    indicators: List[str]


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class AdminPanelLoginBruter(ArtemisBase):
    """
    This module attempts to brute-force login pages of admin panels using common credentials.
    """

    identity = "admin_panel_login_bruter"
    filters = [
        {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
    ]

    def __init__(self) -> None:
        super().__init__()
        self.logger = logging.getLogger(__name__)

    def check_url(self, url: str) -> bool:
        """
        Checks if the given URL is accessible and returns a 200 status code.
        """
        try:
            response = http_requests.get(url)
            return response.status_code == 200 if response else False
        except requests.RequestException as e:
            self.logger.debug(f"Error checking URL {url}: {e}")
            return False

    def discover_login_paths(self, base_url: str) -> List[str]:
        """
        Discovers common admin login paths by checking predefined URLs.
        """
        common_login_paths = [
            "/index.php",
            "/admin/login.php",
            "/admin/index.php",
            "/login",
            "/admin_login",
            "/login/",
            "/admin_login/",
            "/admin-console/",
            "/administration/",
            "/pma/",
            "/cms/",
            "/CMS/",
            "/panel/",
            "/adminpanel/",
            "/backend/",
            "/phpmyadmin/",
            "/login.php",
            "/index.php",
            "/admin/",
            "/admin/login/",
            "/login/",
            "/user/login/",
            "/administrator/",
            "/redirect.php?subject=server&server=:5432:allow",  # PhppgAdmin
            "/",
        ]

        found_paths = []
        for path in common_login_paths:
            full_url = urllib.parse.urljoin(base_url, path)
            if self.check_url(full_url):
                found_paths.append(path)
        return found_paths

    def brute_force_login_path(
        self, base_url: str, login_path: str, username: str, password: str
    ) -> Optional[AdminPanelLoginBruterResult]:
        """
        Attempts to brute-force a login form at the given path using provided credentials.
        """
        self.log.info("Trying %s:%s on %s/%s", username, password, base_url, login_path.lstrip("/"))
        login_url = urllib.parse.urljoin(base_url, login_path)
        session = requests.session()

        try:
            response = self.throttle_request(lambda: http_requests.request("get", login_url, session=session))
            if not response or response.status_code != 200:
                return None

            original_cookies = session.cookies.get_dict()  # type: ignore
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                action = form.get("action")
                form_url = urllib.parse.urljoin(login_url, action) if action else login_url
                inputs = form.find_all("input")

                form_data = {}
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
                        elif "pass" in input_name.lower() or "pwd" in input_name.lower():
                            form_data[input_name] = password
                        else:
                            form_data[input_name] = input_value

                try:
                    post_response = self.throttle_request(
                        lambda: http_requests.request(
                            "post",
                            form_url,
                            data=form_data,
                            session=session,
                        )
                    )
                except requests.RequestException as e:
                    self.logger.debug(f"Error submitting to {form_url}: {e}")
                    continue

                if not post_response:
                    continue

                indicators = []
                login_success = False

                new_cookies = session.cookies.get_dict()  # type: ignore
                if len(new_cookies) > len(original_cookies):
                    indicators.append("session_cookie")
                    login_success = True

                if any(logout_message.lower() in post_response.text.lower() for logout_message in LOGOUT_MESSAGES):
                    indicators.append("logout_link")
                    login_success = True

                failure_detected = any(
                    msg.lower() in post_response.text.lower() and msg.lower() not in response.text.lower()
                    for msg in COMMON_FAILURE_MESSAGES
                )
                self.log.info("indicators: %s failure_detected: %s", indicators, failure_detected)
                if not failure_detected:
                    indicators.append("no_failure_messages")
                    login_success = True
                else:
                    login_success = False

                if login_success and indicators:
                    self.log.info(
                        "successful brute force form_url=%s username=%s password=%s", form_url, username, password
                    )
                    return AdminPanelLoginBruterResult(
                        url=form_url,
                        username=username,
                        password=password,
                        indicators=indicators,
                    )

        except Exception as e:
            self.logger.warning(f"Error during brute force on {login_url}: {e}")

        return None

    def scan(self, task: Task, base_url: str, login_paths: List[str]) -> List[AdminPanelLoginBruterResult]:
        """
        Scans the target URL for vulnerable login paths using common credentials.
        """
        results = []
        credential_pairs = set()
        for path in login_paths:
            for username in COMMON_USERNAMES:
                for password in get_passwords(task):
                    result = self.brute_force_login_path(base_url, path, username, password)
                    if result:
                        results.append(result)
                        credential_pairs.add((username, password))

            # We also try the random password, to make sure we don't "log in" with that password - if we do, that is a false
            # positive.
            if self.brute_force_login_path(
                base_url, path, "this-username-should-not-exist", binascii.hexlify(os.urandom(16)).decode("ascii")
            ):
                results = []
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
            data={"results": [result.dict() for result in results]},
        )


if __name__ == "__main__":
    AdminPanelLoginBruter().loop()
