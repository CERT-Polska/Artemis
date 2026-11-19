Official Docker documentation points to the `moby` repo for the reference default seccomp policy:
https://docs.docker.com/engine/security/seccomp/

The default policy is not committed to this repo: docker/seccomp/update_seccomp_profile.py
fetches it verbatim from the permalink
https://raw.githubusercontent.com/moby/profiles/f862455628f78f84c937e967e4a03902fb1dee11/seccomp/default.json
and adds the extra rule below, producing docker/seccomp/syd.json.

For syd (docker/sandbox.sh), docker-compose.yaml overrides that policy in two ways:
- CAP_SYS_PTRACE - syd supervises sandboxed processes with ptrace(2), which the default
  profile allows only with that capability.
- one extra rule: unshare(2) is allowed when no CLONE_NEW* flag is set. syd's monitor
  thread calls unshare(2) at startup (unsharing CLONE_FS|CLONE_FILES|CLONE_SYSVSEM - no
  namespace flags), which the default profile denies without CAP_SYS_ADMIN (not granted).
  Namespace creation stays blocked - by the rule's mask and by the lack of CAP_SYS_ADMIN.

docker-compose.yaml loads syd.json: the fetched policy plus that rule - a gitignored
artifact. scripts/start generates it via docker/seccomp/update_seccomp_profile.py before
starting the stack; if you call docker compose directly, run the script first (it needs
internet access to fetch the default policy).
