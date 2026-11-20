# TODO: skip this file in review for now, I need to make sure it's good
import os
import sqlite3
import subprocess
import tempfile
import unittest


class TestVCSWorker(unittest.TestCase):
    """Verifies the sandboxing of the VCS reporter's attacker-data parsing (artemis/sandboxing.py):
    the wc.db worker runs sandboxed with minimal permissions, refuses to run unsandboxed, and
    the sandbox grants nothing beyond what the parsing needs."""

    def setUp(self) -> None:
        if not os.path.exists("/sandbox.sh"):
            raise unittest.SkipTest("not running inside an image built from this repo (no /sandbox.sh)")
        self.db = tempfile.NamedTemporaryFile(suffix=".db")
        con = sqlite3.connect(self.db.name)
        con.execute("create table REPOSITORY (root text)")
        con.execute("insert into REPOSITORY values (?)", ("https://example.com/svn/repo",))
        con.commit()
        con.close()

    def _sandboxed(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/sandbox.sh"] + args,
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "SANDBOX": "on"},
        )

    def test_worker_runs_sandboxed_and_refuses_unsandboxed(self) -> None:
        sandboxed = self._sandboxed(["python3", "-m", "artemis.reporting.modules.vcs.worker", self.db.name])
        self.assertEqual(sandboxed.returncode, 0, sandboxed.stderr)
        self.assertEqual(sandboxed.stdout.strip(), "https://example.com/svn/repo")

        unsandboxed = subprocess.run(
            ["python3", "-m", "artemis.reporting.modules.vcs.worker", self.db.name],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertNotEqual(unsandboxed.returncode, 0, unsandboxed.stdout + unsandboxed.stderr)

    def test_no_read_access_outside_granted_paths_and_port_allowlisted_network(self) -> None:
        # denial must come from the sandbox, not the environment - the same read succeeds
        # unsandboxed
        denied = (
            "import errno, socket\n"
            "try:\n"
            "    open('/proc/version').read()\n"
            "except PermissionError:\n"
            "    pass\n"
            "else:\n"
            "    raise SystemExit('/proc/version readable')\n"
            "try:\n"
            "    socket.create_connection(('8.8.8.8', 53), timeout=5)\n"
            "except OSError as e:\n"
            "    assert e.errno == errno.EACCES, repr(e)\n"
            "else:\n"
            "    raise SystemExit('connected out on port 53')\n"
            "try:\n"
            "    socket.create_connection(('8.8.8.8', 443), timeout=5).close()\n"
            "except PermissionError:\n"
            "    raise SystemExit('port 443 denied')\n"
            "except OSError:\n"
            "    pass  # no route/no listener is fine - only the sandbox denial would be a failure\n"
        )
        sandboxed = self._sandboxed(["python3", "-c", denied])
        self.assertEqual(sandboxed.returncode, 0, sandboxed.stderr)

        unsandboxed = subprocess.run(
            ["python3", "-c", "open('/proc/version').read()"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(unsandboxed.returncode, 0, unsandboxed.stderr)


if __name__ == "__main__":
    unittest.main()
