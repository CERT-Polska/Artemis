#!/usr/bin/env bash

# landrun-based sandbox for module containers, wrapping Landlock
# https://github.com/zouuup/landrun
#
# Disabled with SANDBOX=off, extended with SANDBOX_WRITABLE=path:path (extra writable
# directories, e.g. for modules that mount a data volume).
#
# Layers:
#  - only the read-only parts of the image (plus /opt) may be executed, so payloads
#    dropped in writable directories cannot be run,
#  - no TCP connect or listen (Landlock is port-based, so UDP can't be restricted here
#    - internet access is blocked at the Docker level instead),
#    TODO: block UDP egress at the Docker level (e.g. a DOCKER-USER nftables rule dropping
#    UDP except the embedded DNS resolver 127.0.0.11:53),
#  - the filesystem is readable everywhere and writable only in the directories below.
#
# TODO: io_uring bypasses Landlock. Ensure that Docker's seccomp blocks io_uring,
# or block io_uring somehow (e.g. Android blocks io_uring).

set -eu

if [ "${SANDBOX:-on}" != "on" ]; then
    exec "$@"
fi

# Network confinement needs Landlock ABI 4 (kernel >=6.7) and is checked below instead
# of relying on landrun's --best-effort, which would silently drop it on older kernels.
# syscall 444 is LANDLOCK_CREATE_RULESET_VERSION, returns the ABI version.
abi=$(python3 -c 'import ctypes; libc=ctypes.CDLL(None); libc.syscall.restype=ctypes.c_long; print(libc.syscall(444, None, 0, 1))')
if [ "$abi" -lt 4 ]; then
    echo "sandbox: Landlock ABI $abi is too old, network confinement needs kernel >=6.7" >&2
    exit 1
fi

writable_dirs=(/tmp /root /dev/shm /shared /karton-logs /humble)
if [ -n "${SANDBOX_WRITABLE:-}" ]; then
    IFS=: read -r -a extra_writable <<< "$SANDBOX_WRITABLE"
    writable_dirs+=("${extra_writable[@]}")
fi

mkdir -p "${writable_dirs[@]}"

args=(--best-effort --ro / --rox /usr,/bin,/sbin,/lib,/opt --rw /dev/null,/etc/hosts)
while IFS='=' read -r -d '' var _; do
    args+=(--env "$var")
done < <(env -0)
args+=(--rw "$(IFS=,; echo "${writable_dirs[*]}")")

exec landrun "${args[@]}" -- "$@"
