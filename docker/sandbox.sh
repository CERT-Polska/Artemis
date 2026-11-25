#!/usr/bin/env bash

# landrun-based sandbox (https://github.com/zouuup/landrun), wrapping Landlock - used to
# isolate code parsing attacker-controlled data (the VCS reporter, see artemis/sandboxing.py).
#
# TODO: restrict TCP egress to github.com/gitlab.com (e.g. an egress proxy container the
# sandbox connects to, enforcing the host allowlist). Landlock can't restrict UDP egress
# (block it at the Docker level instead), and io_uring bypasses it - both stay open.

set -eu

# Network confinement needs Landlock ABI 4 (kernel >=6.7) and is checked here instead
# of relying on landrun's --best-effort, which would silently drop it on older kernels.
# syscall 444 is LANDLOCK_CREATE_RULESET_VERSION, returns the ABI version.
abi=$(python3 -c 'import ctypes; libc=ctypes.CDLL(None); libc.syscall.restype=ctypes.c_long; print(libc.syscall(444, None, 0, 1))')
if [ "$abi" -lt 4 ]; then
    echo "sandbox: Landlock ABI $abi is too old, network confinement needs kernel >=6.7" >&2
    exit 1
fi

# landrun passes no environment to the command by default - forward everything.
args=(
    --best-effort
    --rox /usr,/bin,/sbin,/lib
    --ro /opt,/etc,/root
    --rw /tmp,/dev/null
    --connect-tcp 80,443
)
while IFS='=' read -r -d '' var _; do
    args+=(--env "$var")
done < <(env -0)

exec landrun "${args[@]}" -- "$@"
