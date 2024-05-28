import socket
from test.e2e.base import BaseE2ETestCase


class ModulesEnablingE2ETestCase(BaseE2ETestCase):
    def test_modules_enabling(self) -> None:
        tag = "modules-enabling-1"
        self.submit_tasks_with_modules_enabled(
            [socket.gethostbyname("test-ftp-server-with-easy-password")], tag, ["port_scanner", "ftp_bruter"]
        )
        self.wait_for_tasks_finished()
        self.assertMessagesContain(
            tag, "Found working credentials for the FTP server: admin:12345, The credentials allow creating files."
        )

        tag = "modules-enabling-2"
        self.submit_tasks_with_modules_enabled([socket.gethostbyname("test-ftp-server-with-easy-password")], tag, [])
        self.wait_for_tasks_finished()
        self.assertMessagesEmpty(tag)

        tag = "modules-enabling-3"
        self.submit_tasks_with_modules_enabled(
            [socket.gethostbyname("test-ftp-server-with-easy-password")], tag, ["port_scanner", "ftp_bruter"]
        )
        self.wait_for_tasks_finished()
        self.assertMessagesContain(
            tag, "Found working credentials for the FTP server: admin:12345, The credentials allow creating files."
        )
