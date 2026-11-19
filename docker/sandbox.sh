#!/usr/bin/env bash

# syd-based sandbox for module containers, based on https://gitlab.exherbo.org/sydbox/sydbox
# (seccomp + landlock; no root, privileges or user namespaces required).
#
# Disabled with SANDBOX=off, extended with SANDBOX_WRITABLE=path:path (extra writable
# directories, e.g. for modules that mount a data volume).
#
# Layers:
#  - exec sandbox: only system/tool directories may be executed, so payloads dropped
#    in writable directories cannot be run,
#  - net sandbox: no network access - nothing may connect or listen,
#  - lock (landlock) sandbox: the filesystem is writable only in the directories
#    below.
#
# Kernel >=5.19 with CONFIG_LSM_LANDLOCK is required. Two landlock-based rules don't
# enforce on older kernels, making the sandbox silently weaker there - the seccomp-based
# layers (exec, net, uring) enforce on every kernel:
#  - allow/lock/connect below (network confinement) needs landlock ABI 4 (kernel >=6.7);
#    on older kernels connect is confined only by the seccomp net sandbox,
#  - truncate confinement needs landlock ABI 3 (kernel >=6.2); the filesystem write
#    confinement itself still applies.
# TODO: unit-test the effective policy and make unsupported layers a hard error (network
# isolation must keep working on kernels 6.1 via the seccomp net sandbox).

set -eu

if [ "${SANDBOX:-on}" != "on" ]; then
    exec "$@"
fi

writable_dirs=(/tmp /root /dev/shm /shared /karton-logs /humble)
if [ -n "${SANDBOX_WRITABLE:-}" ]; then
    IFS=: read -r -a extra_writable <<< "$SANDBOX_WRITABLE"
    writable_dirs+=("${extra_writable[@]}")
fi

# The allow/lock rules below reference these dirs; syd resolves them at startup and
# exits fatally if one is missing, so they must exist even when no volume is mounted.
mkdir -p "${writable_dirs[@]}" 2>/dev/null || true

# io_uring bypasses seccomp-notify, so it is denied altogether on kernels <7.0;
# cpython maps some memory RWX (trace/allow_unsafe_exec_memory).
# Note: sandbox/net:on and sandbox/uring:on ENABLE the corresponding sandboxes, i.e.
# they make network access and io_uring usage denied for the sandboxed process.
# Executable are only the read-only parts of the image - nothing under writable_dirs,
# with /opt being an exception: extra modules keep tools there and the lock sandbox
# keeps its content frozen.
args=(
    -poff
    -m'trace/allow_unsafe_exec_memory:1'
    -m'sandbox/exec:on'
    -m'allow/exec+/usr/***'
    -m'allow/exec+/bin/***'
    -m'allow/exec+/sbin/***'
    -m'allow/exec+/lib/***'
    -m'allow/exec+/opt/***'
    -m'sandbox/uring:on'
    -m'sandbox/net:on'
    -m'sandbox/lock:on'
    -m'allow/lock/read,readdir,exec+/'
)

for dir in "${writable_dirs[@]}"; do
    args+=(-m "allow/lock/write,create,delete,rename,truncate,symlink,mkdir,rmdir,bind+${dir}")
done
args+=(-m 'allow/lock/write,truncate+/dev/null')
# module_base appends to it when ADDITIONAL_HOSTS_FILE_PATH is set
args+=(-m 'allow/lock/write+/etc/hosts')

exec syd "${args[@]}" -- "$@"
