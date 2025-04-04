from freezegun import freeze_time


class PasswordUtilsTest(unittest.TestCase):
    @freeze_time("2023-02-21")
    def test_getting_passwords_domain(self) -> None:
        passwords = self.karton.get_passwords(
            Task(
                headers={"type": TaskType.WEBAPP, "webapp": WebApplication.WORDPRESS},
                payload={"url": "http://www.projectname.example.com"},
            )
        )
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
        passwords = self.karton.get_passwords(
            Task(
                headers={"type": TaskType.WEBAPP, "webapp": WebApplication.WORDPRESS},
                payload={"url": "http://127.0.0.1"},
            )
        )
        self.assertEqual(passwords, PASSWORDS)
