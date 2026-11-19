#!/usr/bin/env python3
"""
Generate docker/seccomp/syd.json.
More info: docker/seccomp/README.txt.
"""

import json
import urllib.request
from pathlib import Path

DIR = Path(__file__).resolve().parent
DEFAULT_PROFILE_URL = (
    "https://raw.githubusercontent.com/moby/profiles/" "f862455628f78f84c937e967e4a03902fb1dee11/seccomp/default.json"
)
RULE = {
    "names": ["unshare"],
    "action": "SCMP_ACT_ALLOW",
    "comment": "Artemis: allow unshare(2) without CLONE_NEW* flags (syd monitor thread)",
    "args": [{"index": 0, "value": 2114060288, "valueTwo": 0, "op": "SCMP_CMP_MASKED_EQ"}],
}

profile = json.loads(urllib.request.urlopen(DEFAULT_PROFILE_URL).read())
profile["syscalls"] = [s for s in profile["syscalls"] if s != RULE] + [RULE]
(DIR / "syd.json").write_text(json.dumps(profile, indent=1) + "\n")
