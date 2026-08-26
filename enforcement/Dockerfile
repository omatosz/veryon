FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY poll-db.sh enforce-netns.sh ./
RUN chmod +x poll-db.sh enforce-netns.sh
