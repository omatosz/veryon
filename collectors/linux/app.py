import os
import re
import time
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

DB_DSN = os.environ["DATABASE_URL"]
LOG_PATH = os.environ.get("AUTH_LOG_PATH", "/hostlogs/auth.log")

INSERT_SQL = """
    INSERT INTO raw_events (ts, source, host, event_type, src_ip, payload)
    VALUES (%s, %s, %s, %s, %s, %s)
"""

# Ex: "2026-08-25T13:40:07.178692-03:00 osn0w sshd[123]: Failed password for root from 1.2.3.4 port 5555 ssh2"
LINE_RE = re.compile(
    r"^(?P<ts>\S+) (?P<host>\S+) (?P<proc>[^:\[]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)
IP_RE = re.compile(r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")


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
        return datetime.fromisoformat(raw)
    except ValueError:
        return datetime.now(timezone.utc)


def classify(proc, msg):
    proc = proc.strip()
    if proc == "sshd":
        if msg.startswith("Accepted"):
            return "linux.ssh.login_success"
        if msg.startswith("Failed password"):
            return "linux.ssh.login_failed"
        if msg.startswith("Invalid user"):
            return "linux.ssh.invalid_user"
        if "Disconnected from" in msg or "Connection closed" in msg:
            return "linux.ssh.disconnected"
        return "linux.ssh.other"
    if proc == "sudo":
        return "linux.sudo.command" if "COMMAND=" in msg else "linux.sudo.session"
    if proc in ("login", "systemd-logind"):
        return "linux.session.event"
    return "linux.auth.other"


def parse_line(line):
    match = LINE_RE.match(line)
    if not match:
        return None

    proc = match.group("proc")
    msg = match.group("msg")
    ip_match = IP_RE.search(msg)

    return {
        "ts": parse_timestamp(match.group("ts")),
        "host": match.group("host"),
        "event_type": classify(proc, msg),
        "src_ip": ip_match.group("ip") if ip_match else None,
        "payload": {"process": proc.strip(), "pid": match.group("pid"), "message": msg},
    }


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
    print(f"linux collector iniciado, lendo {LOG_PATH}", flush=True)

    for line in follow(LOG_PATH):
        line = line.rstrip("\n")
        if not line:
            continue

        event = parse_line(line)
        if event is None:
            print(f"linha ignorada, formato inesperado: {line[:200]}", flush=True)
            continue

        while True:
            try:
                cur.execute(
                    INSERT_SQL,
                    (
                        event["ts"],
                        "linux",
                        event["host"],
                        event["event_type"],
                        event["src_ip"],
                        psycopg2.extras.Json(event["payload"]),
                    ),
                )
                break
            except psycopg2.Error as exc:
                print(f"falha ao gravar evento, tentando de novo em 2s: {exc}", flush=True)
                conn.rollback()
                time.sleep(2)
                conn = connect_db()
                cur = conn.cursor()

        print(f"evento gravado: {event['event_type']} de {event['src_ip']}", flush=True)


if __name__ == "__main__":
    main()
