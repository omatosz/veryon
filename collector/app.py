import json
import os
import time
from datetime import datetime, timezone

import psycopg2

DB_DSN = os.environ["DATABASE_URL"]
LOG_PATH = os.environ.get("COWRIE_LOG_PATH", "/data/cowrie-var/log/cowrie/cowrie.json")

INSERT_SQL = """
    INSERT INTO raw_events (ts, source, host, event_type, src_ip, payload)
    VALUES (%s, %s, %s, %s, %s, %s)
"""


def connect_db():
    while True:
        try:
            conn = psycopg2.connect(DB_DSN)
            conn.autocommit = True
            return conn
        except psycopg2.OperationalError as exc:
            print(f"aguardando banco de dados... ({exc})", flush=True)
            time.sleep(2)


def parse_timestamp(raw):
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)


def follow(path):
    while not os.path.exists(path):
        print(f"aguardando arquivo de log em {path}...", flush=True)
        time.sleep(2)

    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def main():
    conn = connect_db()
    cur = conn.cursor()
    print(f"collector iniciado, lendo {LOG_PATH}", flush=True)

    for line in follow(LOG_PATH):
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            print(f"linha ignorada, JSON invalido: {line[:200]}", flush=True)
            continue

        ts = parse_timestamp(event.get("timestamp"))
        event_type = event.get("eventid", "unknown")
        src_ip = event.get("src_ip")
        host = event.get("sensor", "cowrie")

        while True:
            try:
                cur.execute(INSERT_SQL, (ts, "cowrie", host, event_type, src_ip, json.dumps(event)))
                break
            except psycopg2.Error as exc:
                print(f"falha ao gravar evento, tentando de novo em 2s: {exc}", flush=True)
                conn.rollback()
                time.sleep(2)
                conn = connect_db()
                cur = conn.cursor()

        print(f"evento gravado: {event_type} de {src_ip}", flush=True)


if __name__ == "__main__":
    main()
