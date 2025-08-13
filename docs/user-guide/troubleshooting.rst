Troubleshooting
===============

Startup issues related to port 5000
-----------------------------------
On some configurations (e.g. MacOS using AirPlay Receiver) port 5000 is already used, which will cause Artemis startup issues.
To change that, replace ``ports: ["5000:5000"]`` with e.g. ``ports: ["7500:5000"]`` in ``docker-compose.yaml``.

Startup issues related to non-x86 architectures
-----------------------------------------------
If you are using a non-x86 architecture and see the following message during container build:

.. code-block::

    ------
    ERROR: Could not find a version that satisfies the requirement nassl<6,>=5.1 (from sslyze) (from versions: 0.13.1, 0.13.2, 0.13.4, 0.13.5, 0.13.6, 0.13.7, 0.14.0, 0.14.1, 0.14.2, 0.15.0, 0.15.1, 0.16.0, 0.16.1, 0.16.2, 0.16.3, 0.17.0, 1.0.1, 1.0.2, 1.0.3)

    ERROR: No matching distribution found for nassl<6,>=5.1

We recommend running Artemis on an x86 machine.

Windows build issues
--------------------
If you are using Windows and you see the following message during container build:

.. code-block::

    ------
    RUN cd /nuclei && git apply nuclei-rate-limiting.patch  && cd v2/cmd/nuclei && go build && GOBIN=/usr/local/bin/ go install:
    #85 2.234 error: corrupt patch at line 7

this may mean that during clone you configured Git to change newlines from Linux (``\n``) to Windows (``\r\n``). Changing
this setting will fix the problem.

To solve this, run:

.. code-block::

    git config --global core.autocrlf input

This command sets Git to convert line endings to LF on checkout but doesn't convert them when committing files.
After setting the configuration, you should re-clone your repository to ensure that the line endings are correct in the files.

Shodan module startup issues
----------------------------

If you see the following error in the logs:

.. code-block::

    karton-shodan_vulns-1                  | [ERROR] - [2024-02-04 15:35:04,622] shodan_vulns.py - in <module>() (line 102): Shodan API key is required to start the Shodan vulnerability module.
    karton-shodan_vulns-1                  | [ERROR] - [2024-02-04 15:35:04,622] shodan_vulns.py - in <module>() (line 103): Don't worry - all other modules can be used without this API key.

That means the Shodan module wasn't able to start because an API key was not configured.
To fix this, provide the ``SHODAN_API_KEY`` configuration variable, see :doc:`configuration`.

Issues when scanning localhost
------------------------------
As Artemis modules are Docker containers, you won't be able to scan your host's ``localhost``.
Entering ``localhost`` as the target to scan will cause the modules to scan themselves.

Results disappeared after migrating from an old version of Artemis
------------------------------------------------------------------
If you updated from an old version of Artemis and don't see the scanned targets or scan results anymore,
contact us on Discord: https://discord.gg/GfUW4mZmy9.


Running tests locally
---------------------
If you encounter problem with DNS while running ``scripts/tests`` you may need to set it explicitly.
Example error you may encounter:

.. code-block::

    # main error will be:
    failed to solve: process "/bin/sh -c apk add --no-cache --virtual .build-deps gcc git libc-dev make libffi-dev libpcap-dev postgresql-dev && ...
    # exact reason:
    fatal: unable to access 'https://github.com/CERT-Polska/checkdmarc/': Could not resolve host: github.com
    fatal: could not fetch adddeb056c05d9fa69f4b34d06ae5fcb21948490 from promisor remote
    warning: Clone succeeded, but checkout failed.
    You can inspect what was checked out with 'git status'
    and retry with 'git restore --source=HEAD :/'

According to https://docs.docker.com/engine/network/, containers should use the same DNS servers as the host by default
But there are known issues on Ubuntu distribution regarding to that.

To resolve that you can e.g:

.. code-block::

    # add the following line to /etc/docker/daemon.json
    {"dns": ["8.8.8.8"]}
    # restart your docker
    sudo systemctl restart docker
