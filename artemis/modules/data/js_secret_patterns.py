import re
from typing import List, NamedTuple


class SecretPattern(NamedTuple):
    name: str
    regex: re.Pattern  # type: ignore[type-arg]
    severity: str


SECRET_PATTERNS: List[SecretPattern] = [
    SecretPattern(
        name="AWS Access Key ID",
        regex=re.compile(r"(?:^|[^A-Za-z0-9/+=])(?:AKIA|ASIA)[A-Z0-9]{16}(?:[^A-Za-z0-9/+=]|$)"),
        severity="high",
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        regex=re.compile(
            r"""(?:aws_?secret_?access_?key|AWS_SECRET_ACCESS_KEY)[\s]*[=:]+[\s]*["']?[A-Za-z0-9/+=]{40}["']?""",
            re.IGNORECASE,
        ),
        severity="high",
    ),
    SecretPattern(
        name="Google API Key",
        regex=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        severity="high",
    ),
    SecretPattern(
        name="Google OAuth Secret",
        regex=re.compile(r"GOCSPX-[A-Za-z0-9\-_]{28}"),
        severity="high",
    ),
    SecretPattern(
        name="Slack Token",
        regex=re.compile(r"xox[bpors]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"),
        severity="high",
    ),
    SecretPattern(
        name="Slack Webhook URL",
        regex=re.compile(
            r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}"
        ),
        severity="high",
    ),
    SecretPattern(
        name="GitHub Token",
        regex=re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"),
        severity="high",
    ),
    SecretPattern(
        name="GitHub Fine-Grained Token",
        regex=re.compile(r"github_pat_[A-Za-z0-9_]{22,255}"),
        severity="high",
    ),
    SecretPattern(
        name="GitLab Token",
        regex=re.compile(r"glpat-[0-9a-zA-Z\-_]{20}"),
        severity="high",
    ),
    SecretPattern(
        name="Stripe Secret Key",
        regex=re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,99}"),
        severity="high",
    ),
    SecretPattern(
        name="Stripe Publishable Key",
        regex=re.compile(r"pk_(?:live|test)_[0-9a-zA-Z]{24,99}"),
        severity="medium",
    ),
    SecretPattern(
        name="SendGrid API Key",
        regex=re.compile(r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"),
        severity="high",
    ),
    SecretPattern(
        name="Private Key",
        regex=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        severity="high",
    ),
    SecretPattern(
        name="Hardcoded Bearer Token",
        regex=re.compile(r"""(?:["'])[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}(?:["'])"""),
        severity="high",
    ),
    SecretPattern(
        name="Twilio API Key",
        regex=re.compile(r"SK[0-9a-fA-F]{32}"),
        severity="medium",
    ),
    SecretPattern(
        name="Mailgun API Key",
        regex=re.compile(r"key-[0-9a-zA-Z]{32}"),
        severity="medium",
    ),
    SecretPattern(
        name="JSON Web Token",
        regex=re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}"),
        severity="medium",
    ),
    SecretPattern(
        name="Firebase Database URL",
        regex=re.compile(
            r"""(?:databaseURL|firebase[_.]?(?:url|config|database))[\s]*[=:]+[\s]*["']"""
            r"""https?://[a-z0-9.-]+\.firebaseio\.com/?["']""",
            re.IGNORECASE,
        ),
        severity="medium",
    ),
    SecretPattern(
        name="Hardcoded Password",
        regex=re.compile(
            r"""(?:password|passwd|pwd|secret|api_?key|apikey|api_?secret|access_?token|auth_?token)"""
            r"""[\s]*[=:]+[\s]*["'][A-Za-z0-9\-_\.~!@#$%^&*+=/?]{8,}["']""",
            re.IGNORECASE,
        ),
        severity="medium",
    ),
    SecretPattern(
        name="OpenAI API Key",
        regex=re.compile(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"),
        severity="high",
    ),
    SecretPattern(
        name="Shopify Access Token",
        regex=re.compile(r"shpat_[0-9a-fA-F]{32}"),
        severity="high",
    ),
    SecretPattern(
        name="DigitalOcean Token",
        regex=re.compile(r"dop_v1_[a-z0-9]{64}"),
        severity="high",
    ),
    SecretPattern(
        name="Telegram Bot Token",
        regex=re.compile(r"\d{9,10}:[a-zA-Z0-9_-]{35}"),
        severity="high",
    ),
    SecretPattern(
        name="Discord Bot Token",
        regex=re.compile(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),
        severity="high",
    ),
    SecretPattern(
        name="Discord Webhook URL",
        regex=re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+"),
        severity="high",
    ),
    SecretPattern(
        name="Sentry DSN",
        regex=re.compile(r"https://[a-zA-Z0-9]+@[a-z0-9]+\.ingest\.sentry\.io/\d+"),
        severity="medium",
    ),
    SecretPattern(
        name="Algolia API Key",
        regex=re.compile(
            r"""(?:algolia|application)_?(?:api)?_?key[\s]*[=:]+[\s]*["'][a-zA-Z0-9]{10,}["']""",
            re.IGNORECASE,
        ),
        severity="medium",
    ),
    SecretPattern(
        name="Cloudinary URL",
        regex=re.compile(r"cloudinary://[0-9]{15}:[a-zA-Z0-9]+@[a-zA-Z]+"),
        severity="high",
    ),
    SecretPattern(
        name="New Relic Key",
        regex=re.compile(r"NRII-[a-zA-Z0-9]{20,}"),
        severity="medium",
    ),
    SecretPattern(
        name="Heroku API Key",
        regex=re.compile(
            r"""(?:heroku)[\s]*[=:]+[\s]*["'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["']""",
            re.IGNORECASE,
        ),
        severity="high",
    ),
    SecretPattern(
        name="Database Connection URI",
        regex=re.compile(
            r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis)://[^\s'\"]{10,}",
            re.IGNORECASE,
        ),
        severity="high",
    ),
    SecretPattern(
        name="Microsoft Teams Webhook",
        regex=re.compile(
            r"https://[a-z]+\.webhook\.office\.com/webhookb2/[a-zA-Z0-9@\-]+/[^\s'\"]{10,}"
        ),
        severity="high",
    ),
    SecretPattern(
        name="Facebook Access Token",
        regex=re.compile(r"EAACEdEose0cBA[0-9A-Za-z]+"),
        severity="high",
    ),
    SecretPattern(
        name="Firebase Config API Key",
        regex=re.compile(
            r"""firebaseConfig\s*=\s*\{[^}]*apiKey\s*:\s*['"][^'"]+['"]""",
            re.DOTALL,
        ),
        severity="medium",
    ),
]
