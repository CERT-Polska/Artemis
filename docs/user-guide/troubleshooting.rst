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

MongoDB startup issues
----------------------

MongoDB since version 5 requires AVX support from the CPU. Certain virtualized environments don't support AVX instructions. **We strongly
recommend contacting your cloud provider to enable AVX support for the virtual machine**, but if it's not possible, a workaround for this
is to pin MongoDB to version 4 in ``docker-compose.yaml``. Below are logs which you might see when this is the case:

.. code-block::

    artemis-backend-1  |   File "/usr/local/lib/python3.11/site-packages/pymongo/topology.py", line 238, in _select_servers_loop
    artemis-backend-1  |     raise ServerSelectionTimeoutError(
    artemis-backend-1  | pymongo.errors.ServerSelectionTimeoutError: db:27017: [Errno -2] Name does not resolve, Timeout: 30s, Topology Description: <TopologyDescription id: 64171dc4adf6cec1ffeb07db, topology_type: Unknown, servers: [<ServerDescription ('db', 27017) server_type: Unknown, rtt: None, error=AutoReconnect('db:27017: [Errno -2] Name does not resolve')>]>
    artemis-db-1  |
    artemis-db-1  | WARNING: MongoDB 5.0+ requires a CPU with AVX support, and your current system does not appear to have that!
    artemis-db-1  |   see https://jira.mongodb.org/browse/SERVER-54407
    artemis-db-1  |   see also https://www.mongodb.com/community/forums/t/mongodb-5-0-cpu-intel-g4650-compatibility/116610/2
    artemis-db-1  |   see also https://github.com/docker-library/mongo/issues/485#issuecomment-891991814
    artemis-db-1  |
    artemis-db-1  | /usr/local/bin/docker-entrypoint.sh: line 416:    26 Illegal instruction     "${mongodHackedArgs[@]}" --fork

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
As Artemis modules are Docker containers, you won't be able to scan ``localhost``. Entering ``localhost`` as the target to scan
will cause the containers to scan themselves.
