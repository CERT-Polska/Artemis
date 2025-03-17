FROM python:3.13-alpine3.20

COPY --from=golang:1.23-alpine /usr/local/go/ /usr/local/go/
ENV PATH="/usr/local/go/bin:$PATH"

COPY docker/wait-for-it.sh /wait-for-it.sh
COPY requirements.txt requirements.txt
COPY docker/go.sum docker/go.mod /go/
ARG ADDITIONAL_REQUIREMENTS
# We run a single RUN command to decrease layer size - e.g. the final `apk del .build-deps` will
# remove some apk packages.
# Whois here is important - if we wouldn't install it, we would default to busybox whois,
# having different output making https://pypi.org/project/whoisdomain/ regexes fail.
RUN apk add --no-cache --virtual .build-deps gcc git libc-dev make libffi-dev libpcap-dev postgresql-dev && \
    apk add --no-cache bash libpcap libpq git subversion whois coreutils && \
    cd /go && \
    GOBIN=/usr/local/bin/ go install -modfile go.mod github.com/projectdiscovery/naabu/v2/cmd/naabu && \
    GOBIN=/usr/local/bin/ go install -modfile go.mod github.com/praetorian-inc/fingerprintx/cmd/fingerprintx && \
    GOBIN=/usr/local/bin/ go install -modfile go.mod github.com/lc/gau/v2/cmd/gau && \
    GOBIN=/usr/local/bin/ go install -modfile go.mod github.com/projectdiscovery/subfinder/v2/cmd/subfinder && \
    GOBIN=/usr/local/bin/ go install -modfile go.mod github.com/projectdiscovery/nuclei/v3/cmd/nuclei && \
    cd / && \
    git clone https://github.com/rfc-st/humble.git --branch master /humble && \
    git clone https://github.com/CERT-Polska/joomla-scanner.git --branch main /joomla-scanner && \
    pip install --no-cache-dir -r requirements.txt -r /humble/requirements.txt $ADDITIONAL_REQUIREMENTS && \
    apk del .build-deps

WORKDIR /opt

COPY "artemis/" "artemis/"
COPY "alembic.ini" "alembic.ini"
COPY "migrations/" "migrations/"
COPY "static/" "static/"
COPY "templates/" "templates/"
COPY "docker/wait-for-dependencies.sh" "/wait-for-dependencies.sh"

# Warmup the cache. That way if the user is in an environment where requests to remote APIs (e.g. providing WordPress
# version check) fail, the response will be served from an on-disk cache.
RUN DB_CONN_STR=unused POSTGRES_CONN_STR=unused REDIS_CONN_STR=unused python3 -m artemis.fallback_api_cache


ENTRYPOINT ["/wait-for-dependencies.sh"]
CMD ["bash", "-c", "alembic upgrade head && uvicorn artemis.main:app --host 0.0.0.0 --port 5000"]
