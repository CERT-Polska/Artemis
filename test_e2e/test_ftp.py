import socket

from test_e2e.base import BaseE2ETestCase


class FTPE2ETestCase(BaseE2ETestCase):
    def test_ftp(self) -> None:
        self.submit_tasks([socket.gethostbyname("test-ftp-server-with-easy-password")])
        self.wait_for_tasks_finished()
        messages = self.get_task_messages()
        self.assertTrue("Found working credentials for the FTP server: admin:12345" in messages)
