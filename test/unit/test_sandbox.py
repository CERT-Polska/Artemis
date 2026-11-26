import unittest

from artemis.sandboxing import SANDBOX_CHECKS_SH, SandboxProfile, run_sandboxed


class TestSandbox(unittest.TestCase):
    def test_checks_pass_under_every_profile(self) -> None:
        # Each profile's subset of the checks (short sh functions in sandbox_checks.sh, argument in
        # line with the SandboxProfile enum) must pass inside the sandbox of that profile.
        for profile in SandboxProfile:
            with self.subTest(profile=profile.name):
                run_sandboxed(["sh", SANDBOX_CHECKS_SH, profile.name], profile=profile)


if __name__ == "__main__":
    unittest.main()
