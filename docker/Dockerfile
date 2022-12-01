FROM python:3.10-alpine3.16

COPY docker/wait-for-it.sh /wait-for-it.sh

RUN apk add --no-cache --virtual .build-deps go gcc libc-dev make libffi-dev libpcap-dev postgresql-dev && \
    apk add --no-cache bash libpcap libpq
RUN GOBIN=/usr/local/bin/ go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    GOBIN=/usr/local/bin/ go install github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

RUN apk del .build-deps

WORKDIR /opt

COPY "artemis/" "artemis/"
COPY "static/" "static/"
COPY "templates/" "templates/"

CMD ["uvicorn", "artemis.main:app", "--host", "0.0.0.0", "--port", "5000"]
