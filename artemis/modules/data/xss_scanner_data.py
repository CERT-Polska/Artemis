"""XSS Scanner data module for loading payloads."""
from os.path import dirname

# Common XSS payloads including advanced evasion techniques
with open(f"{dirname(__file__)}/xss_payloads.txt", "r") as f:
    XSS_PAYLOADS = f.read().splitlines()
    XSS_PAYLOADS = [payload.strip() for payload in XSS_PAYLOADS if payload.strip() and not payload.startswith("#")]

# XSS Detection Indicators - patterns that indicate successful XSS injection
XSS_INDICATORS = [
    # JavaScript execution indicators
    "<script>",
    "</script>",
    "javascript:",
    "onerror=",
    "onload=",
    "onfocus=",
    "onmouseover=",
    "onclick=",
    "onbegin=",
    "onstart=",
    "ontoggle=",
    "onpageshow=",
    "onhashchange=",
    # Common alert/confirm/prompt patterns
    "alert(",
    "confirm(",
    "prompt(",
    "eval(",
    # Data URIs
    "data:text/html",
    "data:text/javascript",
    # SVG-based XSS
    "<svg",
    "</svg>",
    # Event handler attributes
    "autofocus",
    "formaction=",
    # HTML entities that may indicate reflected input
    "&#",
    "&#x",
    # Template injection indicators
    "{{",
    "}}",
    "${",
    "<%=",
]
