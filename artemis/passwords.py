import copy
import datetime
from typing import List

from artemis import utils
from artemis.config import Config

PASSWORDS = [
    "admin",
    "administrator",
    "admin1",
    "password",
    "haslo",
    "1234",
    "12345",
    "123456",
    "123456789",
    "qwerty",
    "zaq123wsx",
]


def get_passwords_for_url(url: str) -> List[str]:
    passwords = copy.copy(PASSWORDS)
    host = utils.get_host_from_url(url)

    if not utils.is_ip_address(host):
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
