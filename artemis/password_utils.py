import datetime
from typing import List

from karton.core import Task

from artemis import ip_utils, task_utils, utils
from artemis.config import Config

PASSWORDS = {
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
    "zaq12wsx",
} | set(Config.Miscellaneous.PASSWORD_BRUTER_ADDITIONAL_PASSWORDS)


def get_passwords(current_task: Task) -> List[str]:
    passwords = list(PASSWORDS)
    host = utils.get_host_from_url(task_utils.get_target_url(current_task))

    if not ip_utils.is_ip_address(host):
        domain_items = host.split(".")
        while domain_items and domain_items[0] in Config.Miscellaneous.STRIPPED_PREFIXES:
            domain_items = domain_items[1:]

        if domain_items:
            site_name = domain_items[0]

            passwords.append(site_name + "123")
            passwords.append(site_name + "1")
            for year_relative in [0, -1, -2, -3]:
                passwords.append(site_name + str(datetime.datetime.now().year + year_relative))
    return passwords
