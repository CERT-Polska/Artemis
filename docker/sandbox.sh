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
#  - net sandbox: outgoing connections allowed anywhere (modules scan arbitrary
#    targets and talk to Redis/S3), but nothing may listen,
#  - lock (landlock) sandbox: the filesystem is writable only in the directories
#    below; on kernels <6.2 truncate confinement and on <6.7 landlock port
#    confinement are no-ops (the seccomp layers above still enforce).
#
# Kernel >=5.19 and CONFIG_LSM_LANDLOCK are required.

set -eu

if [ "${SANDBOX:-on}" != "on" ]; then
    exec "$@"
fi

writable_dirs=(/tmp /root /dev/shm /shared /karton-logs /humble)
if [ -n "${SANDBOX_WRITABLE:-}" ]; then
    IFS=: read -r -a extra_writable <<< "$SANDBOX_WRITABLE"
    writable_dirs+=("${extra_writable[@]}")
fi

# syd refuses to start if an allow/lock path does not exist (ENOENT is fatal)
mkdir -p "${writable_dirs[@]}" 2>/dev/null || true

# io_uring bypasses seccomp-notify, so it is denied altogether on kernels <7.0;
# cpython maps some memory RWX (trace/allow_unsafe_exec_memory).
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
    -m'allow/net/connect+tcp!0.0.0.0/0!0-65535'
    -m'allow/net/connect+udp!0.0.0.0/0!0-65535'
    -m'allow/net/connect+tcp!::/0!0-65535'
    -m'allow/net/connect+udp!::/0!0-65535'
    -m'sandbox/lock:on'
    -m'allow/lock/read,readdir,exec+/'
)

for dir in "${writable_dirs[@]}"; do
    args+=(-m "allow/lock/write,create,delete,rename,truncate,symlink,mkdir,rmdir,bind+${dir}")
done
args+=(-m 'allow/lock/write,truncate+/dev/null')
# module_base appends to it when ADDITIONAL_HOSTS_FILE_PATH is set
args+=(-m 'allow/lock/write+/etc/hosts')

# Additional kernel-enforced ("landlock") layer for connect on kernels >=6.7; no-op below.
args+=(-m 'allow/lock/connect+0-65535')

exec syd "${args[@]}" -- "$@"
