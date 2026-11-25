import unittest

from artemis.sandboxing import SANDBOX_CHECKS_SH, SandboxProfile, run_sandboxed


class TestSandbox(unittest.TestCase):
    def test_checks_pass_under_every_level(self) -> None:
        # Each level's subset of the checks (short sh functions in sandbox_checks.sh, argument in
        # line with the SandboxProfile enum) must pass inside the sandbox of that level.
        for level in SandboxProfile:
            with self.subTest(level=level.name):
                run_sandboxed(["sh", SANDBOX_CHECKS_SH, level.name], profile=level)


if __name__ == "__main__":
    unittest.main()
