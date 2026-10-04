"""
High-confidence regular expressions for detecting secrets leaked in JavaScript files.

Each pattern is designed to match a well-known secret format with a low false-positive
rate.  Generic high-entropy token detection is intentionally omitted because it produces
too much noise when run against minified production bundles.

Sources / references for the patterns used here:
  - https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
  - https://stripe.com/docs/api/authentication
  - https://api.slack.com/authentication/token-types
"""

import re
from typing import Dict, List, NamedTuple, Pattern


class SecretPattern(NamedTuple):
    """Describes a single secret detection rule.

    Attributes:
        name: Human-readable label shown in reports, e.g. "AWS Access Key ID".
        pattern: Compiled regex that matches the secret value.
        description: Short explanation of why this pattern matters (used in
            documentation and UI tooltips).
    """

    name: str
    pattern: Pattern[str]
    description: str


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------
# Each entry is a ``SecretPattern`` so that downstream code can iterate
# uniformly over name, compiled regex **and** description without reaching
# into multiple data-structures.
#
# IMPORTANT: Only add patterns that have a very low false-positive rate.
# If you add a new pattern, please update the unit tests in
# ``test/unit/test_js_secret_patterns.py`` accordingly.
# ---------------------------------------------------------------------------

SECRET_PATTERNS: List[SecretPattern] = [
    # -- Cloud providers -----------------------------------------------------
    SecretPattern(
        name="AWS Access Key ID",
        pattern=re.compile(
            r"(?:^|[^A-Za-z0-9])"  # word boundary (avoid matching inside longer tokens)
            r"((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})"
            r"(?:$|[^A-Za-z0-9])"
        ),
        description=(
            "AWS IAM access key IDs always start with AKIA (long-term) or ASIA "
            "(temporary STS) followed by 16 uppercase alphanumeric characters."
        ),
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=re.compile(
            r"(?i)"  # case-insensitive preamble to match key names like "aws_secret_access_key"
            r"(?:aws_secret_access_key|aws_secret_key|secret_access_key)"
            r"""[\s:='"]+"""
            r"(?-i:([A-Za-z0-9/+=]{40}))"  # the actual 40-char base-64 key is case-sensitive
            # NOTE: (?-i:...) is a Python 3.6+ *inline* flag that **locally disables**
            # the IGNORECASE flag from the outer (?i).  If you need to support Python < 3.6,
            # split this into two separate patterns.
        ),
        description="AWS secret access keys are 40-character base-64 strings.",
    ),
    SecretPattern(
        name="Google API Key",
        pattern=re.compile(r"""(?:^|[^A-Za-z0-9_-])(AIza[0-9A-Za-z\-_]{35})(?:$|[^A-Za-z0-9_-])"""),
        description="Google / GCP API keys start with 'AIza' followed by 35 URL-safe characters.",
    ),
    # -- Code hosting --------------------------------------------------------
    SecretPattern(
        name="GitHub Token",
        pattern=re.compile(r"(gh[pousr]_[A-Za-z0-9_]{36,255})"),
        description=(
            "GitHub classic personal access tokens (ghp_), OAuth tokens (gho_), "
            "user-to-server tokens (ghu_), server-to-server tokens (ghs_), and "
            "refresh tokens (ghr_)."
        ),
    ),
    # -- Payment providers ---------------------------------------------------
    SecretPattern(
        name="Stripe API Key",
        pattern=re.compile(r"((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99})"),
        description="Stripe standard (sk_) and restricted (rk_) API keys for live or test mode.",
    ),
    # -- Communication -------------------------------------------------------
    SecretPattern(
        name="Slack Token",
        pattern=re.compile(r"(xox[pboasa]-[0-9]{10,13}-[0-9]{10,13}(?:-[0-9a-zA-Z]{24,34}){1,2})"),
        description=(
            "Slack API tokens: bot (xoxb-), user (xoxp-), app-level (xoxa-), "
            "and legacy (xoxo-, xoxs-)."
        ),
    ),
    # -- Cryptographic material ----------------------------------------------
    SecretPattern(
        name="Private Key",
        pattern=re.compile(r"-----BEGIN\s(?:RSA|DSA|EC|OPENSSH|PGP)\sPRIVATE\sKEY-----"),
        description="PEM-encoded private key header (RSA, DSA, EC, OPENSSH, or PGP).",
    ),
    # -- Heroku --------------------------------------------------------------
    SecretPattern(
        name="Heroku API Key",
        pattern=re.compile(
            r"(?i)heroku.*['\"\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        ),
        description="Heroku API keys are UUID-v4 strings, typically preceded by an identifying label.",
    ),
    # -- Twilio --------------------------------------------------------------
    SecretPattern(
        name="Twilio API Key",
        pattern=re.compile(r"(SK[0-9a-fA-F]{32})"),
        description="Twilio API keys start with 'SK' followed by 32 hex characters.",
    ),
]

# Pre-build a plain dict for callers that only need name → compiled pattern,
# matching the interface the scanner module expects.
SECRET_REGEXES: Dict[str, Pattern[str]] = {sp.name: sp.pattern for sp in SECRET_PATTERNS}
