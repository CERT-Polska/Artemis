import os
import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "data" / "sandbox_breakout.sh"


class TestSandbox(unittest.TestCase):
    def _run(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, capture_output=True, text=True, timeout=300)

    def test_breakout_attempts_fail_sandboxed_and_succeed_outside(self) -> None:
        if not os.path.exists("/sandbox.sh"):
            raise unittest.SkipTest("not running inside an image built from this repo (no /sandbox.sh)")

        wrapped = self._run(["/sandbox.sh", "bash", str(SCRIPT)])
        if "allowed: execute-frozen-binary" not in wrapped.stdout:
            raise unittest.SkipTest(f"syd failed to start: {wrapped.stderr.strip()}")

        unwrapped = self._run(["bash", str(SCRIPT)])

        # inside the sandbox: no vector escapes and no legitimate operation is blocked
        self.assertEqual(wrapped.returncode, 0, wrapped.stdout + wrapped.stderr)
        self.assertNotIn("escaped:", wrapped.stdout)
        self.assertNotIn("sandbox-broken:", wrapped.stdout)

        # outside the sandbox: every vector would succeed, proving the attempts test
        # real behavior and not e.g. missing binaries
        self.assertNotIn("denied:", unwrapped.stdout, unwrapped.stdout + unwrapped.stderr)
        self.assertNotIn("sandbox-broken:", unwrapped.stdout, unwrapped.stdout + unwrapped.stderr)
        self.assertGreater(unwrapped.returncode, 0)


if __name__ == "__main__":
    unittest.main()
