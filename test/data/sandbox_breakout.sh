#!/usr/bin/env bash

# A stand-in for a malicious module payload: tries to escape the syd sandbox
# (docker/sandbox.sh) the ways exploited payloads would. Prints one line per
# vector and exits with the number of successful breakouts, which is every
# vector when run unsandboxed and none when run through /sandbox.sh - what
# test.unit.test_sandbox asserts about both runs.

# no set -e: a vector failing IS the tested outcome
set -u

breakouts=0

attempt() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "escaped: $name"
        breakouts=$((breakouts + 1))
    else
        echo "denied: $name"
    fi
}

# What a sandbox must not break: a denied legitimate operation is as broken as an
# allowed breakout, so a failing control counts towards the exit code as well.
legitimate() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "allowed: $name"
    else
        echo "sandbox-broken: $name"
        breakouts=$((breakouts + 1))
    fi
}

# payloads dropped in writable directories must not be executable
attempt execute-dropped-payload bash -c 'p=$(mktemp /tmp/payload.XXXXXX); printf "#!/bin/sh\necho pwned\n" > "$p"; chmod +x "$p"; "$p"'

# module code must stay frozen: a payload must not persist inside it
attempt persist-in-module-dir bash -c 'touch /opt/artemis-persistence-test'

# nothing may listen, so a payload cannot await its operator
attempt listen-on-socket python3 -c 'import socket; socket.socket().bind(("127.0.0.1", 0))'

# frozen binaries keep working (the exec sandbox allows image content only)
legitimate execute-frozen-binary /bin/true

# outgoing connections keep working; ECONNREFUSED means the network stack answered,
# i.e. connect(2) itself went through
legitimate outgoing-connection python3 -c '
import socket
try:
    socket.create_connection(("127.0.0.1", 9), timeout=10).close()
except ConnectionRefusedError:
    pass
'

echo "breakouts: $breakouts"
exit "$breakouts"
