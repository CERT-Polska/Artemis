from os.path import dirname

with open(f"{dirname(__file__)}/lfi_detector_payloads.txt", "r") as f:
    lines = f.read().splitlines()
    LFI_PAYLOADS = [line.strip() for line in lines if not line.startswith("#")]

with open(f"{dirname(__file__)}/rce_payloads.txt", "r") as f:
    lines = f.read().splitlines()
    RCE_PAYLOADS = [line.strip() for line in lines if not line.startswith("#")]
