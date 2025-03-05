from os.path import dirname

# Common LFI payloads
with open(f"{dirname(__file__)}/lfi_detector_payloads.txt", "r") as f:
    LFI_PAYLOADS = f.read().splitlines()
    LFI_PAYLOADS = [payload.strip() for payload in LFI_PAYLOADS if not payload.startswith("#")]

print(LFI_PAYLOADS)
