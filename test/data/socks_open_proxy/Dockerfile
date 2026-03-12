FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y microsocks \
 && rm -rf /var/lib/apt/lists/*

EXPOSE 1080

CMD ["microsocks","-p","1080"]
