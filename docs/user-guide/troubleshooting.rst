Troubleshooting
===============

Startup issues related to port 5000
-----------------------------------
On some configurations (e.g. MacOS using AirPlay Receiver) port 5000 is already used, which will cause Artemis startup issues.
To change that, replace ``ports: ["5000:5000"]`` with e.g. ``ports: ["7500:5000"]`` in ``docker-compose.yaml``.

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

No results for modules communicating via e.g. HTTP
--------------------------------------------------
If you don't see any results when scanning with modules that work with HTTP services (such as e.g.
``bruter``, ``joomla_scanner``, ``wp_scanner``) or (more generally) services on a particular port (i.e. not
domains), make sure the ``port_scanner`` module is enabled.
