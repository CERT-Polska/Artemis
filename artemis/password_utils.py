import copy
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
} | {
    # Top50 passwords from https://cert.pl/hasla/
    "123456",
    "qwerty",
    "12345",
    "123456789",
    "zaq12wsx",
    "1234",
    "12345678",
    "polska",
    "111111",
    "misiek",
    "monika",
    "marcin",
    "mateusz",
    "agnieszka",
    "123qwe",
    "1234567890",
    "1qaz2wsx",
    "1234567",
    "qwerty123",
    "qwerty1",
    "123123",
    "0000",
    "bartek",
    "damian",
    "michal",
    "qwe123",
    "polska1",
    "password",
    "karolina",
    "kacper",
    "maciek",
    "samsung",
    "qwertyuiop",
    "zxcvbnm",
    "kasia",
    "1q2w3e4r",
    "kochanie",
    "lol123",
    "kasia1",
    "natalia",
    "myszka",
    "11111",
    "1qazxsw2",
    "lukasz",
    "mateusz1",
    "komputer",
    "666666",
    "qazwsx",
    "piotrek",
    "daniel",
}


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
