import socket
from test.e2e.base import BaseE2ETestCase


class FTPE2ETestCase(BaseE2ETestCase):
    def test_ftp(self) -> None:
        self.submit_tasks([socket.gethostbyname("test-ftp-server-with-easy-password")])
        self.wait_for_tasks_finished()
        self.assertMessagesContain("Found working credentials for the FTP server: admin:12345")
