#!/usr/bin/env python3
"""
Generate docker/seccomp/syd.json.
More info: docker/seccomp/README.txt.
"""

import json
from pathlib import Path

DIR = Path(__file__).resolve().parent.parent / "docker" / "seccomp"
RULE = {
    "names": ["unshare"],
    "action": "SCMP_ACT_ALLOW",
    "comment": "Artemis: allow unshare(2) without CLONE_NEW* flags (syd monitor thread)",
    "args": [{"index": 0, "value": 2114060288, "valueTwo": 0, "op": "SCMP_CMP_MASKED_EQ"}],
}

profile = json.loads((DIR / "default.json").read_text())
profile["syscalls"] = [s for s in profile["syscalls"] if s != RULE] + [RULE]
(DIR / "syd.json").write_text(json.dumps(profile, indent=1) + "\n")
