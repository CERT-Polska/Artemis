from os.path import dirname

# Load basic XSS payloads
with open(f"{dirname(__file__)}/basic_xss_payloads.txt", "r") as f:
    lines = f.read().splitlines()
    BASIC_XSS_PAYLOADS = [line.strip() for line in lines if line.strip() and not line.startswith("#")]

# Load encoding bypass payloads
with open(f"{dirname(__file__)}/encoding_bypass_payloads.txt", "r") as f:
    lines = f.read().splitlines()
    ENCODING_BYPASS_PAYLOADS = [line.strip() for line in lines if line.strip() and not line.startswith("#")]

# Load filter evasion payloads
with open(f"{dirname(__file__)}/filter_evasion_payloads.txt", "r") as f:
    lines = f.read().splitlines()
    FILTER_EVASION_PAYLOADS = [line.strip() for line in lines if line.strip() and not line.startswith("#")]

# Load WAF bypass payloads
with open(f"{dirname(__file__)}/waf_bypass_payloads.txt", "r") as f:
    lines = f.read().splitlines()
    WAF_BYPASS_PAYLOADS = [line.strip() for line in lines if line.strip() and not line.startswith("#")]

# Load context-aware payloads
with open(f"{dirname(__file__)}/context_aware_payloads.txt", "r") as f:
    lines = f.read().splitlines()
    CONTEXT_AWARE_PAYLOADS = [line.strip() for line in lines if line.strip() and not line.startswith("#")]

# Load framework bypass payloads
with open(f"{dirname(__file__)}/framework_bypass_payloads.txt", "r") as f:
    lines = f.read().splitlines()
    FRAMEWORK_BYPASS_PAYLOADS = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
