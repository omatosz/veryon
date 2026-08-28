"""
Servico de varredura.

Roda em duas formas:

    docker compose up -d scanner              servico, consome a fila scan_jobs
    docker compose run --rm scanner --once    uma varredura e sai (modo antigo)

O modo servico existe pro botao "Rodar varredura agora" na tela funcionar de
verdade: a API so enfileira uma linha em scan_jobs, e quem executa e este
processo. Em qualquer um dos dois modos, o achado bruto vai pra raw_events e
depois e normalizado em vulnerabilities pelo normalize.py.
"""

import argparse
import json
import os
import subprocess
import time
import xml.etree.ElementTree as ET

import psycopg2

from normalize import count_disappeared, normalize_new_events

DB_DSN = os.environ["DATABASE_URL"]
NMAP_TARGETS = [t.strip() for t in os.environ.get("NMAP_TARGETS", "").split(",") if t.strip()]
NUCLEI_TARGETS = [t.strip() for t in os.environ.get("NUCLEI_TARGETS", "").split(",") if t.strip()]
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "5"))

INSERT_SQL = """
    INSERT INTO raw_events (ts, source, host, event_type, src_ip, payload)
    VALUES (now(), 'scanner', %s, %s, %s, %s)
"""

# Pega um trabalho da fila e marca como rodando na mesma instrucao. O
# SKIP LOCKED garante que dois scanners nunca peguem o mesmo job, mesmo se
# alguem subir uma segunda replica.
CLAIM_JOB = """
    UPDATE scan_jobs SET status = 'running', started_at = now()
    WHERE id = (
        SELECT id FROM scan_jobs WHERE status = 'queued'
        ORDER BY created_at LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING id, started_at
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
        classification = info.get("classification") or {}
        payload = {
            "template_id": finding.get("template-id"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "cve": classification.get("cve-id"),
            # O nuclei so traz score em parte dos templates. Quando nao vem, o
            # normalizador deriva da severidade.
            "cvss": classification.get("cvss-score"),
            "matched_at": finding.get("matched-at"),
            "description": info.get("description"),
        }
        cur.execute(INSERT_SQL, (label, "scanner.nuclei.finding", None, json.dumps(payload)))
        found += 1

    print(f"[nuclei] {label}: {found} achado(s) gravado(s)", flush=True)


def run_all_scans(cur):
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


def process_job(cur, job_id, started_at):
    print(f"[job {job_id}] varredura iniciada", flush=True)
    try:
        run_all_scans(cur)
        stats = normalize_new_events(cur)
        # So conta como sumido o que estava aberto num ativo que esta varredura
        # realmente reavaliou. Nao fecho sozinho, so reporto, porque sumir do
        # scan tambem acontece quando o alvo cai.
        stats["sumiram"] = count_disappeared(cur, started_at, stats.pop("ativos", []))
        cur.execute(
            "UPDATE scan_jobs SET status='done', finished_at=now(), stats=%s WHERE id=%s",
            (json.dumps(stats), job_id),
        )
        print(f"[job {job_id}] concluida: {stats}", flush=True)
    except Exception as exc:  # noqa: BLE001
        # Varredura que falha nao pode deixar o job preso em 'running' pra
        # sempre, senao o botao na tela nunca mais libera.
        cur.execute(
            "UPDATE scan_jobs SET status='failed', finished_at=now(), error=%s WHERE id=%s",
            (str(exc)[:1000], job_id),
        )
        print(f"[job {job_id}] falhou: {exc}", flush=True)


def serve():
    conn = connect_db()
    cur = conn.cursor()
    print(
        f"scanner iniciado em modo servico: {len(NMAP_TARGETS)} alvo(s) nmap, "
        f"{len(NUCLEI_TARGETS)} alvo(s) nuclei",
        flush=True,
    )

    while True:
        try:
            cur.execute(CLAIM_JOB)
            row = cur.fetchone()
            if row:
                process_job(cur, row[0], row[1])
            else:
                # Sem trabalho na fila, ainda assim normaliza o que tiver
                # chegado por fora (execucao manual com --once, por exemplo).
                normalize_new_events(cur)
        except psycopg2.Error as exc:
            print(f"erro de banco, reconectando: {exc}", flush=True)
            conn = connect_db()
            cur = conn.cursor()

        time.sleep(POLL_SECONDS)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--once",
        action="store_true",
        help="Roda uma varredura, normaliza os achados e sai (comportamento antigo)",
    )
    args = parser.parse_args()

    if not args.once:
        serve()
        return

    conn = connect_db()
    cur = conn.cursor()
    run_all_scans(cur)
    stats = normalize_new_events(cur)
    print(f"scan finalizado: {stats}", flush=True)


if __name__ == "__main__":
    main()
