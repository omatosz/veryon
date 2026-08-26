"""
Coletor de eventos do Windows Event Log (canal Security).

Roda nativamente no Windows (fora do Docker/WSL) porque a API de Event Log
so existe no Windows. Le eventos via win32evtlog (API EvtQuery/EvtNext,
a mesma usada por ferramentas de SOC), filtra por Event ID relevante via
XPath e grava em raw_events, igual aos outros coletores.

Precisa rodar como Administrador (ou usuario no grupo local
"Event Log Readers") para conseguir abrir o canal Security.
"""

import json
import os
import time
import xml.etree.ElementTree as ET
from datetime import datetime

import psycopg2
import win32evtlog
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

DB_DSN = os.environ.get(
    "DATABASE_URL_HOST",
    f"postgresql://{os.environ.get('POSTGRES_USER', 'socadmin')}:"
    f"{os.environ.get('POSTGRES_PASSWORD', 'changeme')}@localhost:"
    f"{os.environ.get('POSTGRES_PORT', '5432')}/{os.environ.get('POSTGRES_DB', 'socsiem')}",
)
STATE_FILE = os.path.join(os.path.dirname(__file__), "last_record.txt")
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "5"))
CHANNEL = "Security"

# Event IDs classicos de telemetria de SOC (logon, privilegio, criacao de processo/conta)
EVENT_TYPE_MAP = {
    4624: "windows.logon.success",
    4625: "windows.logon.failed",
    4672: "windows.logon.privileged",
    4688: "windows.process.created",
    4720: "windows.account.created",
    4732: "windows.group.member_added",
}
XPATH_QUERY = "*[System[(" + " or ".join(f"EventID={eid}" for eid in EVENT_TYPE_MAP) + ")]]"

INSERT_SQL = """
    INSERT INTO raw_events (ts, source, host, event_type, src_ip, payload)
    VALUES (%s, %s, %s, %s, %s, %s)
"""

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def connect_db():
    while True:
        try:
            conn = psycopg2.connect(DB_DSN)
            conn.autocommit = True
            return conn
        except psycopg2.OperationalError as exc:
            print(f"aguardando banco de dados... ({exc})", flush=True)
            time.sleep(2)


def load_last_record():
    if os.path.exists(STATE_FILE):
        content = open(STATE_FILE).read().strip()
        if content:
            return int(content)
    return None  # None = primeira execucao, ainda sem baseline


def save_last_record(record_id):
    with open(STATE_FILE, "w") as f:
        f.write(str(record_id))


def extract_fields(xml_str):
    root = ET.fromstring(xml_str)
    system = root.find(f"{NS}System")
    event_id = int(system.find(f"{NS}EventID").text)
    record_id = int(system.find(f"{NS}EventRecordID").text)
    time_created = system.find(f"{NS}TimeCreated").attrib["SystemTime"]
    computer = system.find(f"{NS}Computer").text

    data = {}
    event_data = root.find(f"{NS}EventData")
    if event_data is not None:
        for d in event_data.findall(f"{NS}Data"):
            data[d.attrib.get("Name", "")] = d.text

    src_ip = data.get("IpAddress")
    if src_ip in ("-", "::1", "127.0.0.1", None, ""):
        src_ip = None

    return {
        "event_id": event_id,
        "record_id": record_id,
        "ts": datetime.fromisoformat(time_created.replace("Z", "+00:00")),
        "host": computer,
        "src_ip": src_ip,
        "data": data,
    }


def newest_record_id():
    """Usado so na primeira execucao, para nao importar o historico inteiro do log."""
    handle = win32evtlog.EvtQuery(
        CHANNEL,
        win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
        XPATH_QUERY,
    )
    events = win32evtlog.EvtNext(handle, 1)
    if not events:
        return 0
    fields = extract_fields(win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml))
    return fields["record_id"]


def poll_new_events(last_record_id):
    """Varre o log de tras pra frente (mais recente primeiro) e para assim que
    encontra um record_id ja processado -- evita re-escanear o log inteiro
    a cada ciclo."""
    handle = win32evtlog.EvtQuery(
        CHANNEL,
        win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
        XPATH_QUERY,
    )
    collected = []
    while True:
        events = win32evtlog.EvtNext(handle, 20)
        if not events:
            break
        stop = False
        for event in events:
            fields = extract_fields(win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml))
            if fields["record_id"] <= last_record_id:
                stop = True
                break
            collected.append(fields)
        if stop:
            break
    return list(reversed(collected))  # devolve em ordem cronologica


def main():
    conn = connect_db()
    cur = conn.cursor()

    last_record_id = load_last_record()
    if last_record_id is None:
        last_record_id = newest_record_id()
        save_last_record(last_record_id)
        print(f"primeira execucao: baseline definida no record {last_record_id} (sem importar historico)", flush=True)

    print(f"windows collector iniciado, canal={CHANNEL}, ultimo record={last_record_id}", flush=True)

    while True:
        try:
            for fields in poll_new_events(last_record_id):
                event_type = EVENT_TYPE_MAP.get(fields["event_id"], f"windows.event.{fields['event_id']}")
                cur.execute(
                    INSERT_SQL,
                    (fields["ts"], "windows", fields["host"], event_type, fields["src_ip"], json.dumps(fields["data"])),
                )
                last_record_id = fields["record_id"]
                print(f"evento gravado: {event_type} (record {last_record_id})", flush=True)
            save_last_record(last_record_id)
        except psycopg2.Error as exc:
            print(f"falha ao gravar evento, tentando de novo em 2s: {exc}", flush=True)
            conn.rollback()
            conn = connect_db()
            cur = conn.cursor()
        except Exception as exc:
            print(f"erro ao consultar Event Log: {exc}", flush=True)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
