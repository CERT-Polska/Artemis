from unittest import TestCase

from freezegun import freeze_time

from artemis.passwords import PASSWORDS, get_passwords_for_url


class GetPasswordsTestCase(TestCase):
    @freeze_time("2023-02-21")
    def test_getting_passwords_domain(self) -> None:
        passwords = get_passwords_for_url("http://www.projectname.example.com")
        self.assertEqual(
            passwords,
            PASSWORDS
            + [
                "projectname123",
                "projectname1",
                "projectname2023",
                "projectname2022",
                "projectname2021",
                "projectname2020",
            ],
        )

    def test_getting_passwords_ip(self) -> None:
        passwords = get_passwords_for_url(
            "http://127.0.0.1",
        )
        self.assertEqual(passwords, PASSWORDS)
