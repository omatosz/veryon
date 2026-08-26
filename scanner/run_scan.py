"""
Dispara Nmap (varredura de portas/servicos) e Nuclei (templates de
vulnerabilidade web) contra os alvos configurados e grava os achados em
raw_events, no mesmo formato usado pelos outros coletores.

Roda como job sob demanda (docker compose run --rm scanner), nao como
servico continuo -- um "scan" e um evento pontual, nao um stream.
"""

import json
import os
import subprocess
import time
import xml.etree.ElementTree as ET

import psycopg2

DB_DSN = os.environ["DATABASE_URL"]
NMAP_TARGETS = [t.strip() for t in os.environ.get("NMAP_TARGETS", "").split(",") if t.strip()]
NUCLEI_TARGETS = [t.strip() for t in os.environ.get("NUCLEI_TARGETS", "").split(",") if t.strip()]

INSERT_SQL = """
    INSERT INTO raw_events (ts, source, host, event_type, src_ip, payload)
    VALUES (now(), 'scanner', %s, %s, %s, %s)
"""


def split_label(spec):
    """'juice-shop@host.docker.internal:3000' -> ('juice-shop', 'host.docker.internal:3000').
    Sem '@', o proprio endereco vira o rotulo (ex: 'db:5432' -> ('db', 'db:5432'))."""
    label, sep, rest = spec.partition("@")
    return (label, rest) if sep else (label, label)


def connect_db():
    while True:
        try:
            conn = psycopg2.connect(DB_DSN)
            conn.autocommit = True
            return conn
        except psycopg2.OperationalError as exc:
            print(f"aguardando banco de dados... ({exc})", flush=True)
            time.sleep(2)


def run_nmap(cur, target_spec):
    label, address = split_label(target_spec)
    host, _, port = address.partition(":")
    print(f"[nmap] escaneando {label} ({host}:{port})...", flush=True)
    cmd = ["nmap", "-sV", "-Pn", "-oX", "-"]
    cmd += ["-p", port] if port else []
    cmd.append(host)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    target = label
    if result.returncode != 0:
        print(f"[nmap] falhou para {target}: {result.stderr[:300]}", flush=True)
        return

    root = ET.fromstring(result.stdout)
    src_ip = None
    address = root.find(".//address")
    if address is not None:
        src_ip = address.attrib.get("addr")

    found = 0
    for port_el in root.findall(".//port"):
        state = port_el.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue

        service = port_el.find("service")
        payload = {
            "port": int(port_el.attrib["portid"]),
            "protocol": port_el.attrib["protocol"],
            "service": service.attrib.get("name") if service is not None else None,
            "product": service.attrib.get("product") if service is not None else None,
            "version": service.attrib.get("version") if service is not None else None,
        }
        cur.execute(INSERT_SQL, (target, "scanner.nmap.port_open", src_ip, json.dumps(payload)))
        found += 1

    print(f"[nmap] {target}: {found} porta(s) aberta(s) gravada(s)", flush=True)


def run_nuclei(cur, target_spec):
    label, target_url = split_label(target_spec)
    print(f"[nuclei] escaneando {label} ({target_url})... (pode demorar na primeira vez, baixa templates)", flush=True)
    result = subprocess.run(
        ["nuclei", "-u", target_url, "-jsonl", "-silent",
         "-timeout", "15", "-retries", "2", "-c", "10"],
        capture_output=True, text=True, timeout=600,
    )
    if result.returncode not in (0, 1):  # nuclei retorna 1 quando so nao acha nada
        print(f"[nuclei] falhou para {label}: {result.stderr[:300]}", flush=True)
        return

    found = 0
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = finding.get("info", {})
        payload = {
            "template_id": finding.get("template-id"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "cve": info.get("classification", {}).get("cve-id"),
            "matched_at": finding.get("matched-at"),
            "description": info.get("description"),
        }
        cur.execute(INSERT_SQL, (label, "scanner.nuclei.finding", None, json.dumps(payload)))
        found += 1

    print(f"[nuclei] {label}: {found} achado(s) gravado(s)", flush=True)


def main():
    conn = connect_db()
    cur = conn.cursor()

    for target in NMAP_TARGETS:
        try:
            run_nmap(cur, target)
        except subprocess.TimeoutExpired:
            print(f"[nmap] timeout escaneando {target}", flush=True)
        except ET.ParseError as exc:
            print(f"[nmap] saida XML invalida para {target}: {exc}", flush=True)

    for target_url in NUCLEI_TARGETS:
        try:
            run_nuclei(cur, target_url)
        except subprocess.TimeoutExpired:
            print(f"[nuclei] timeout escaneando {target_url}", flush=True)

    print("scan finalizado", flush=True)


if __name__ == "__main__":
    main()
