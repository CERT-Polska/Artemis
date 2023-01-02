import socket
from test.e2e.base import BaseE2ETestCase


class NucleiE2ETestCase(BaseE2ETestCase):
    def test_nuclei_phpmyadmin(self) -> None:
        self.submit_tasks([socket.gethostbyname("test-phpmyadmin-easy-password-subdirectory")])
        self.wait_for_tasks_finished()
        self.assertMessagesContain("[high] phpMyAdmin default admin credentials were discovered")
