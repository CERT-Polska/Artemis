Troubleshooting
===============

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
