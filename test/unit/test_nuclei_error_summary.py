import json
import unittest
from typing import Any

from artemis.modules.nuclei import Nuclei


class _CapturingLog:
    """Minimal stand-in for self.log that records info calls."""

    def __init__(self) -> None:
        self.info_calls: list[tuple[str, tuple[Any, ...]]] = []

    def info(self, fmt: str, *args: Any) -> None:
        self.info_calls.append((fmt, args))

    def messages(self) -> list[str]:
        """The format strings of every logged message."""
        return [fmt for fmt, _ in self.info_calls]

    def args_for(self, prefix: str) -> tuple[Any, ...] | None:
        """Return the args tuple of the first message starting with prefix, or None."""
        for fmt, args in self.info_calls:
            if fmt.startswith(prefix):
                return args
        return None

    def payload_for(self, prefix: str) -> Any:
        """The last arg (the aggregated dict) of the message starting with prefix, or None."""
        args = self.args_for(prefix)
        return args[-1] if args else None


class _StubNuclei:
    """Carries just the log attribute the method under test needs."""

    def __init__(self) -> None:
        self.log = _CapturingLog()


def _deadline_error() -> str:
    return 'cause="context deadline exceeded (Client.Timeout exceeded while awaiting headers)"'


def _run(lines: list[str]) -> _CapturingLog:
    stub = _StubNuclei()
    # Call unbound so we don't trigger the heavy Nuclei.__init__.
    Nuclei._log_nuclei_error_summary(stub, lines)  # type: ignore[arg-type]
    return stub.log


class TestLogNucleiErrorSummary(unittest.TestCase):
    def test_collapses_template_paths_of_one_target(self) -> None:
        # Three different template paths on the same target must aggregate to one entry -
        # the target, not the path, is what's actionable and what a re-run passes to -target.
        lines = [
            json.dumps({"input": "https://10.255.255.1:443/backend/", "error": _deadline_error()}),
            json.dumps({"input": "https://10.255.255.1:443/XUI", "error": _deadline_error()}),
            json.dumps({"input": "https://10.255.255.1:443/opensso/UI/Login", "error": _deadline_error()}),
            # A plaintext [WRN] line and a truncated JSON line must both be skipped
            # (continue / json.JSONDecodeError) without breaking aggregation.
            '[WRN] [openam-panel] Could not execute request: cause="context deadline exceeded"',
            '{"input": "https://10.255.255.1:443/broken", "error":',
        ]

        args = _run(lines).args_for("Targets that caused")
        assert args is not None
        distinct_count, targets = args

        self.assertEqual(targets, {"10.255.255.1:443": 3})
        self.assertEqual(distinct_count, 1)

    def test_logs_distinct_target_count(self) -> None:
        # The explicit distinct-target count is the number that answers "does the slow chunk
        # time out on a few targets or most of them" - assert it's logged, not eyeballed.
        lines = [
            json.dumps({"input": "https://10.255.255.1:443/a", "error": _deadline_error()}),
            json.dumps({"input": "https://10.255.255.1:443/b", "error": _deadline_error()}),
            json.dumps({"input": "https://10.255.255.2:443/a", "error": _deadline_error()}),
            json.dumps({"input": "https://example.com:443/a", "error": _deadline_error()}),
        ]

        args = _run(lines).args_for("Targets that caused")
        assert args is not None
        distinct_count, targets = args

        self.assertEqual(
            targets,
            {"10.255.255.1:443": 2, "10.255.255.2:443": 1, "example.com:443": 1},
        )
        self.assertEqual(distinct_count, 3)

    def test_falls_back_to_address_when_no_input(self) -> None:
        # `address` (resolved IP:port) is only used when `input` is absent, e.g. low-level
        # errors that never reached the request-building stage.
        lines = [json.dumps({"address": "10.255.255.1:443", "error": _deadline_error()})]

        args = _run(lines).args_for("Targets that caused")
        assert args is not None
        distinct_count, targets = args

        self.assertEqual(targets, {"10.255.255.1:443": 1})
        self.assertEqual(distinct_count, 1)

    def test_no_deadline_errors_does_not_log_targets(self) -> None:
        lines = [
            json.dumps({"input": "https://10.255.255.1:443/", "error": 'cause="connect: connection refused"'}),
            json.dumps({"input": "https://10.255.255.1:443/ok", "error": "none"}),
        ]

        log = _run(lines)

        # Robust against a reworded message: assert no logged line is about deadline
        # targets at all, rather than relying on one exact prefix.
        for message in log.messages():
            self.assertNotIn("deadline", message.lower())
            self.assertNotIn("Targets that caused", message)


if __name__ == "__main__":
    unittest.main()
