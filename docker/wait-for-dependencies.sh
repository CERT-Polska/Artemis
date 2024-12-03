#!/bin/bash

# We use this file instead of docker-compose depends_on mechanism as depends_on is not taken
# into account on restarts.

/wait-for-it.sh --quiet --timeout=30 -h s3mock -p 9090
/wait-for-it.sh --quiet --timeout=30 -h redis -p 6379
/wait-for-it.sh --quiet --timeout=30 -h postgres -p 5432

exec "$@"
