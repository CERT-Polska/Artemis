#!/bin/sh
# Sandbox checks, run only inside the landrun sandbox (artemis/sandboxing): one short function per
# check, grouped into a subset per SandboxProfile level. $1 is the level name, in line with the
# SandboxProfile enum in python.
# Exits nonzero on the first failing check.
set -e

deny_write_outside_scratch() { for dir in / /opt /tmp /root; do ! echo x > "$dir/artemis-sandbox-check" || return 1; done; }
deny_read_proc() { ! /bin/cat /proc/version; }
deny_python() { ! /usr/local/bin/python3 -c pass; }
deny_listen() { ! /bin/nc -l -p 13337; }
deny_payload_exec() { /bin/cp /bin/echo "$SANDBOX_TMP/payload"; /bin/chmod +x "$SANDBOX_TMP/payload"; ! "$SANDBOX_TMP/payload"; }
deny_connect() { ! /bin/bash -c "exec 3<>/dev/tcp/8.8.8.8/$1"; }
# Landlock here can't restrict UDP
allow_udp() { /bin/bash -c "echo x > /dev/udp/8.8.8.8/$1"; }
deny_scratch_write() { ! echo x > "$SANDBOX_TMP/check"; }
allow_python() { /usr/local/bin/python3 -c 'print(1)' > /dev/null; }
allow_connect_443() { /bin/bash -c "exec 3<>/dev/tcp/8.8.8.8/443"; }
allow_scratch_write() { echo x > "$SANDBOX_TMP/check"; }
allow_frozen_binary() { /bin/true; }
allow_git_config() {
    printf '[remote "origin"]\nurl = https://example.invalid/r\n' > "$SANDBOX_TMP/config"
    [ "$(/usr/bin/git config -f "$SANDBOX_TMP/config" --get remote.origin.url)" = "https://example.invalid/r" ]
}

checks_LV_STRICT() {
    allow_frozen_binary
    deny_write_outside_scratch
    deny_read_proc
    deny_python
    deny_listen
    deny_connect 53
    allow_udp 53
    deny_connect 443
}

checks_LV_VCS() {
    allow_git_config
    deny_write_outside_scratch
    deny_read_proc
    deny_python
    deny_listen
    deny_connect 53
    allow_udp 53
    deny_connect 443
}

checks_LV_PYTHON() {
    allow_python
    allow_scratch_write
    deny_payload_exec
    deny_write_outside_scratch
    deny_read_proc
    deny_listen
    deny_connect 53
    allow_udp 53
    deny_connect 443
}

checks_LV_INTERNET() {
    allow_python
    allow_connect_443
    allow_scratch_write
    allow_frozen_binary
    deny_payload_exec
    deny_write_outside_scratch
    deny_read_proc
    deny_listen
    deny_connect 53
    allow_udp 53
}

"checks_$1"
