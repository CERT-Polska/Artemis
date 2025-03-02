# Common parameters vulnerable to LFI
LFI_PARAMS = ["file", "page", "load"]

# Common LFI payloads
with open("lfi_detector_payloads.txt", "r") as f:
    LFI_PAYLOADS = f.read().splitlines()
    LFI_PAYLOADS = [payload.strip() for payload in LFI_PAYLOADS]