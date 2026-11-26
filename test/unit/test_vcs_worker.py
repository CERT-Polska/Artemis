import sqlite3
import sys
import tempfile
import unittest

from artemis.sandboxing import SandboxProfile, run_sandboxed

REMOTE_URL = "https://example.invalid/svn/repo"


class TestVCSWorker(unittest.TestCase):
    """Verifies that the sandboxed worker (artemis/sandboxing/read_remote_url_from_repository_sqlite.py)
    parses the attacker-controlled wc.db handed over as a readonly path."""

    def setUp(self) -> None:
        self.db = tempfile.NamedTemporaryFile(suffix=".db")
        con = sqlite3.connect(self.db.name)
        con.execute("create table REPOSITORY (root text)")
        con.execute("insert into REPOSITORY values (?)", (REMOTE_URL,))
        con.commit()
        con.close()

    def test_worker_runs_sandboxed(self) -> None:
        sandboxed = run_sandboxed(
            [sys.executable, "-m", "artemis.sandboxing_payloads.read_remote_url_from_repository_sqlite", self.db.name],
            profile=SandboxProfile.NOTCP_PYTHON,
            additional_readonly_paths=[self.db.name],
        ).decode()
        self.assertEqual(sandboxed.strip(), REMOTE_URL)


if __name__ == "__main__":
    unittest.main()
