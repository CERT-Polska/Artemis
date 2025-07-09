from os.path import dirname

with open(f"{dirname(__file__)}/swagger.txt", "r") as f:
    COMMON_SPEC_PATHS = f.read().splitlines()
    COMMON_SPEC_PATHS = [payload.strip() for payload in COMMON_SPEC_PATHS if not payload.startswith("#")]

VULN_DETAILS_MAP = {
    "Endpoint performs HTTP verb which is not documented": "Unsupported HTTP Method",
    "One or more parameter is vulnerable to SQL Injection Attack": "SQL Injection",
    "Endpoint might be vulnerable to SQli": "SQL Injection",
    "Endpoint might be vulnerable to BOLA": "BOLA",
    "Endpoint might be vulnerable to BOPLA": "BOPLA",
    "One or more parameter is vulnerable to OS Command Injection Attack": "OS Command Injection",
    "One or more parameter is vulnerable to XSS/HTML Injection Attack": "XSS/HTML Injection",
    "One or more parameter is vulnerable to SSTI Attack": "SSTI",
    "Endpoint fails to implement security authentication as defined": "Missing Authentication",
}
