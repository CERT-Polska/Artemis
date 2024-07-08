FROM python:3.11-alpine3.19

COPY docker/wait-for-it.sh /wait-for-it.sh
COPY requirements.txt requirements.txt
COPY docker/patches/nuclei-rate-limiting.patch /

ARG ADDITIONAL_REQUIREMENTS
# We run a single RUN command to decrease layer size - e.g. the final `apk del .build-deps` will
# remove some apk packages.
# Whois here is important - if we wouldn't install it, we would default to busybox whois,
# having different output making https://pypi.org/project/whoisdomain/ regexes fail.
RUN apk add --no-cache --virtual .build-deps go gcc git libc-dev make libffi-dev libpcap-dev postgresql-dev && \
    apk add --no-cache bash libpcap libpq git subversion whois && \
    GOBIN=/usr/local/bin/ go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.1 && \
    GOBIN=/usr/local/bin/ go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@v1.1.13 && \
    GOBIN=/usr/local/bin/ go install github.com/lc/gau/v2/cmd/gau@v2.2.3 && \
    GOBIN=/usr/local/bin/ go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6 && \
    git clone https://github.com/projectdiscovery/nuclei.git -b v2.9.7 /nuclei && \
    cd /nuclei && git apply /nuclei-rate-limiting.patch && cd v2/cmd/nuclei && go build && GOBIN=/usr/local/bin/ go install && cd / && rm -rf /nuclei && \
    git clone https://github.com/rfc-st/humble.git --branch master /humble && \
    pip install --no-cache-dir -r requirements.txt -r /humble/requirements.txt $ADDITIONAL_REQUIREMENTS && \
    apk del .build-deps

WORKDIR /opt

COPY "artemis/" "artemis/"
COPY "alembic.ini" "alembic.ini"
COPY "migrations/" "migrations/"
COPY "static/" "static/"
COPY "templates/" "templates/"

# Warmup the cache. That way if the user is in an environment where requests to remote APIs (e.g. providing WordPress
# version check) fail, the response will be served from an on-disk cache.
RUN DB_CONN_STR=unused POSTGRES_CONN_STR=unused REDIS_CONN_STR=unused python3 -m artemis.fallback_api_cache

CMD ["bash", "-c", "alembic upgrade head && uvicorn artemis.main:app --host 0.0.0.0 --port 5000"]
