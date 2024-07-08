FROM python:3.11-alpine3.20

COPY docker/wait-for-it.sh /wait-for-it.sh
COPY requirements.txt requirements.txt
COPY docker/patches/nuclei-rate-limiting.patch /
COPY docker/go.sum docker/go.mod /go/
ARG ADDITIONAL_REQUIREMENTS
# We run a single RUN command to decrease layer size - e.g. the final `apk del .build-deps` will
# remove some apk packages.
# Whois here is important - if we wouldn't install it, we would default to busybox whois,
# having different output making https://pypi.org/project/whoisdomain/ regexes fail.
RUN apk add --no-cache --virtual .build-deps go gcc git libc-dev make libffi-dev libpcap-dev postgresql-dev && \
    apk add --no-cache bash libpcap libpq git subversion whois && \
    cd /go && \
    GOBIN=/usr/local/bin/ go install -modfile go.mod github.com/projectdiscovery/naabu/v2/cmd/naabu && \
    GOBIN=/usr/local/bin/ go install -modfile go.mod github.com/praetorian-inc/fingerprintx/cmd/fingerprintx && \
    GOBIN=/usr/local/bin/ go install -modfile go.mod github.com/lc/gau/v2/cmd/gau && \
    GOBIN=/usr/local/bin/go install -modfile go.mod github.com/projectdiscovery/subfinder/v2/cmd/subfinder && \
    NUCLEI_VERSION=$(grep 'github.com/projectdiscovery/nuclei/v2' go.mod | sed -E 's/.*v([0-9]+\.[0-9]+\.[0-9]+).*/\1/') && \
    git clone https://github.com/projectdiscovery/nuclei.git -b v$NUCLEI_VERSION /nuclei && \
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

CMD ["bash", "-c", "alembic upgrade head && uvicorn artemis.main:app --host 0.0.0.0 --port 5000"]
