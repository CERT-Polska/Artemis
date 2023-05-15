FROM python:3.11-alpine3.17

COPY docker/wait-for-it.sh /wait-for-it.sh

RUN apk add --no-cache --virtual .build-deps go gcc git libc-dev make libffi-dev libpcap-dev postgresql-dev && \
    apk add --no-cache bash libpcap libpq
RUN GOBIN=/usr/local/bin/ go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.1.6 && \
    GOBIN=/usr/local/bin/ go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@v1.1.9 && \
    GOBIN=/usr/local/bin/ go install github.com/lc/gau/v2/cmd/gau@v2.1.2

RUN git clone https://github.com/projectdiscovery/nuclei.git -b v2.9.4 /nuclei
COPY docker/patches/nuclei-rate-limiting.patch /nuclei/
RUN cd /nuclei && git apply nuclei-rate-limiting.patch  && cd v2/cmd/nuclei && go build && GOBIN=/usr/local/bin/ go install

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

RUN apk del .build-deps

WORKDIR /opt

COPY "artemis/" "artemis/"
COPY "static/" "static/"
COPY "templates/" "templates/"

CMD ["uvicorn", "artemis.main:app", "--host", "0.0.0.0", "--port", "5000"]
