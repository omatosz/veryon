"""
Motor de deteccao: avalia as regras Sigma em rules/ contra raw_events e
grava correspondencias em alerts.

Duas categorias de regra:
- Regras normais (a maioria): casadas evento a evento, conforme chegam.
- Regras com bloco "threshold" (extensao propria, ver sigma_eval.py):
  contagem/janela de tempo (ex: N falhas de login do mesmo IP em X minutos),
  avaliadas via agregacao SQL direta, nao evento a evento.
"""

import json
import os
import time

import psycopg2
import psycopg2.extras

from sigma_eval import evaluate, flatten_event, load_rules

DB_DSN = os.environ["DATABASE_URL"]
RULES_DIR = os.environ.get("RULES_DIR", "/app/rules")
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "10"))

INSERT_ALERT_SQL = """
    INSERT INTO alerts (ts, rule_id, title, level, mitre_technique,
                         source_event_id, source_event_type, source_host,
                         source_ip, description, payload)
    VALUES (now(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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


def extract_mitre(tags):
    for tag in tags or []:
        if tag.startswith("attack.t") and tag[8:9].isdigit():
            return "T" + tag[8:].upper()
    return None


def get_checkpoint(cur):
    cur.execute("SELECT last_event_id FROM detection_checkpoint WHERE id = 1")
    return cur.fetchone()[0]


def save_checkpoint(cur, last_event_id):
    cur.execute("UPDATE detection_checkpoint SET last_event_id = %s WHERE id = 1", (last_event_id,))


def fire_alert(cur, rule, event_row, event=None):
    mitre = extract_mitre(rule.get("tags"))
    payload = {"rule_file": rule["_file"], "matched_fields": event or {}}
    cur.execute(
        INSERT_ALERT_SQL,
        (
            rule["id"],
            rule["title"],
            rule["level"],
            mitre,
            event_row.get("id"),
            event_row.get("event_type"),
            event_row.get("host"),
            event_row.get("src_ip"),
            rule.get("description", "").strip(),
            json.dumps(payload),
        ),
    )
    print(f"[alerta] {rule['id']} ({rule['level']}): {rule['title']}", flush=True)


def run_event_rules(cur, event_rules, last_event_id):
    cur.execute(
        "SELECT id, ts, source, host, event_type, src_ip, payload "
        "FROM raw_events WHERE id > %s ORDER BY id",
        (last_event_id,),
    )
    rows = cur.fetchall()
    if not rows:
        return last_event_id

    columns = [desc[0] for desc in cur.description]
    for row in rows:
        event_row = dict(zip(columns, row))
        flat = flatten_event(event_row)
        for rule in event_rules:
            try:
                if evaluate(rule, flat):
                    fire_alert(cur, rule, event_row, flat)
            except ValueError as exc:
                print(f"[detection] erro avaliando {rule['_file']}: {exc}", flush=True)
        last_event_id = event_row["id"]

    return last_event_id


GROUP_BY_ALLOWLIST = {"src_ip", "host"}


def run_threshold_rules(cur, threshold_rules):
    for rule in threshold_rules:
        th = rule["threshold"]
        event_type = rule["detection"]["selection"].get("event_type")
        group_by = th["group_by"]
        if group_by not in GROUP_BY_ALLOWLIST:
            print(f"[detection] group_by invalido em {rule['_file']}: {group_by}", flush=True)
            continue

        cur.execute(
            f"""
            SELECT {group_by}, count(*) AS n
            FROM raw_events
            WHERE event_type = %s
              AND ts > now() - make_interval(mins => %s)
              AND {group_by} IS NOT NULL
            GROUP BY {group_by}
            HAVING count(*) >= %s
            """,
            (event_type, th["timeframe_minutes"], th["count"]),
        )
        for group_value, n in cur.fetchall():
            # cooldown: nao repetir o mesmo alerta se ja disparamos um para
            # esse grupo dentro da mesma janela de tempo
            cur.execute(
                f"""
                SELECT 1 FROM alerts
                WHERE rule_id = %s AND source_{('ip' if group_by == 'src_ip' else 'host')} = %s
                  AND ts > now() - make_interval(mins => %s)
                LIMIT 1
                """,
                (rule["id"], group_value, th["timeframe_minutes"]),
            )
            if cur.fetchone():
                continue

            fake_event_row = {
                "id": None,
                "event_type": event_type,
                "host": group_value if group_by == "host" else None,
                "src_ip": group_value if group_by == "src_ip" else None,
            }
            fire_alert(cur, rule, fake_event_row, {"count": n, "group_by": group_by, "group_value": group_value})


def main():
    conn = connect_db()
    cur = conn.cursor()

    rules = load_rules(RULES_DIR)
    event_rules = [r for r in rules if "threshold" not in r]
    threshold_rules = [r for r in rules if "threshold" in r]
    print(
        f"detection engine iniciado: {len(event_rules)} regra(s) por evento, "
        f"{len(threshold_rules)} regra(s) de limiar",
        flush=True,
    )

    while True:
        try:
            last_event_id = get_checkpoint(cur)
            last_event_id = run_event_rules(cur, event_rules, last_event_id)
            save_checkpoint(cur, last_event_id)
            run_threshold_rules(cur, threshold_rules)
        except psycopg2.Error as exc:
            print(f"erro de banco, reconectando: {exc}", flush=True)
            conn.rollback()
            conn = connect_db()
            cur = conn.cursor()

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
