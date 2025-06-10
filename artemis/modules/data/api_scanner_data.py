from os.path import dirname

# Common LFI payloads
with open(f"{dirname(__file__)}/swagger.txt", "r") as f:
    COMMON_SPEC_PATHS = f.read().splitlines()
    COMMON_SPEC_PATHS = [payload.strip() for payload in COMMON_SPEC_PATHS if not payload.startswith("#")]
