import socket
from test.e2e.base import BaseE2ETestCase


class FTPE2ETestCase(BaseE2ETestCase):
    def test_ftp_only_port(self) -> None:
        tag = "ftp-e2e-only-port"
        self.submit_tasks([socket.gethostbyname("test-ftp-server-with-easy-password") + ":21"], tag=tag)
        self.wait_for_tasks_finished()
        self.assertMessagesContain(
            tag, "Found working credentials for the FTP server: admin:12345, The credentials allow creating files."
        )

    def test_ftp_ip_range(self) -> None:
        tag = "ftp-e2e-ip-range"
        self.submit_tasks([socket.gethostbyname("test-ftp-server-with-easy-password") + "/32"], tag=tag)
        self.wait_for_tasks_finished()
        self.assertMessagesContain(
            tag, "Found working credentials for the FTP server: admin:12345, The credentials allow creating files."
        )

    def test_ftp(self) -> None:
        tag = "ftp-e2e"
        self.submit_tasks([socket.gethostbyname("test-ftp-server-with-easy-password")], tag=tag)
        self.wait_for_tasks_finished()
        self.assertMessagesContain(
            tag, "Found working credentials for the FTP server: admin:12345, The credentials allow creating files."
        )
