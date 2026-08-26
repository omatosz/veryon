"""
Enriquece IPs vistos em raw_events com reputacao de tres fontes de threat
intel (AbuseIPDB, VirusTotal, OTX) e grava o resultado em ip_enrichment.

Roda em loop continuo processando IPs novos/desatualizados, mas tambem
aceita `--ip X.X.X.X` para enriquecer um IP especifico sob demanda -- util
porque o trafego que a gente proprio gera e quase todo interno (rede
docker, host), entao raramente ha um IP publico de verdade pra enriquecer
organicamente numa demo.
"""

import argparse
import ipaddress
import os
import time

import psycopg2
import psycopg2.extras
import requests

DB_DSN = os.environ["DATABASE_URL"]
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
OTX_API_KEY = os.environ.get("OTX_API_KEY")

POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "60"))
TTL_HOURS = int(os.environ.get("TTL_HOURS", "24"))
MAX_PER_CYCLE = int(os.environ.get("MAX_PER_CYCLE", "5"))

UPSERT_SQL = """
    INSERT INTO ip_enrichment (
        ip, checked_at, abuseipdb_score, abuseipdb_country, abuseipdb_isp,
        abuseipdb_total_reports, virustotal_malicious, virustotal_total_engines,
        virustotal_reputation, otx_pulse_count, raw_payload
    ) VALUES (%s, now(), %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (ip) DO UPDATE SET
        checked_at = EXCLUDED.checked_at,
        abuseipdb_score = EXCLUDED.abuseipdb_score,
        abuseipdb_country = EXCLUDED.abuseipdb_country,
        abuseipdb_isp = EXCLUDED.abuseipdb_isp,
        abuseipdb_total_reports = EXCLUDED.abuseipdb_total_reports,
        virustotal_malicious = EXCLUDED.virustotal_malicious,
        virustotal_total_engines = EXCLUDED.virustotal_total_engines,
        virustotal_reputation = EXCLUDED.virustotal_reputation,
        otx_pulse_count = EXCLUDED.otx_pulse_count,
        raw_payload = EXCLUDED.raw_payload
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


def is_public(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)


def query_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        return None
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json().get("data")
    except requests.RequestException as exc:
        print(f"[abuseipdb] falhou para {ip}: {exc}", flush=True)
        return None


def query_virustotal(ip):
    if not VIRUSTOTAL_API_KEY:
        return None
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json().get("data")
    except requests.RequestException as exc:
        print(f"[virustotal] falhou para {ip}: {exc}", flush=True)
        return None


def query_otx(ip):
    if not OTX_API_KEY:
        return None
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        print(f"[otx] falhou para {ip}: {exc}", flush=True)
        return None


def enrich_ip(cur, ip):
    print(f"[threatintel] enriquecendo {ip}...", flush=True)
    abuse = query_abuseipdb(ip)
    vt = query_virustotal(ip)
    otx = query_otx(ip)

    vt_stats = (vt or {}).get("attributes", {}).get("last_analysis_stats", {})

    cur.execute(
        UPSERT_SQL,
        (
            ip,
            (abuse or {}).get("abuseConfidenceScore"),
            (abuse or {}).get("countryCode"),
            (abuse or {}).get("isp"),
            (abuse or {}).get("totalReports"),
            vt_stats.get("malicious"),
            sum(vt_stats.values()) if vt_stats else None,
            (vt or {}).get("attributes", {}).get("reputation"),
            (otx or {}).get("pulse_info", {}).get("count"),
            psycopg2.extras.Json({"abuseipdb": abuse, "virustotal": vt, "otx": otx}),
        ),
    )
    score = (abuse or {}).get("abuseConfidenceScore")
    malicious = vt_stats.get("malicious")
    pulses = (otx or {}).get("pulse_info", {}).get("count")
    print(
        f"[threatintel] {ip}: abuseipdb={score} virustotal_malicious={malicious} otx_pulses={pulses}",
        flush=True,
    )


def find_candidates(cur, limit):
    cur.execute(
        """
        SELECT DISTINCT re.src_ip
        FROM raw_events re
        LEFT JOIN ip_enrichment ie ON ie.ip = re.src_ip
        WHERE re.src_ip IS NOT NULL
          AND (ie.ip IS NULL OR ie.checked_at < now() - make_interval(hours => %s))
        LIMIT %s
        """,
        (TTL_HOURS, limit * 10),  # margem, boa parte pode ser IP privado e sera descartada abaixo
    )
    return [row[0] for row in cur.fetchall() if is_public(row[0])][:limit]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", help="Enriquece um IP especifico e sai (ignora o filtro de IP publico e o TTL)")
    args = parser.parse_args()

    conn = connect_db()
    cur = conn.cursor()

    if args.ip:
        enrich_ip(cur, args.ip)
        return

    print(f"threatintel iniciado: TTL={TTL_HOURS}h, ate {MAX_PER_CYCLE} IP(s) por ciclo", flush=True)
    while True:
        try:
            candidates = find_candidates(cur, MAX_PER_CYCLE)
            for i, ip in enumerate(candidates):
                enrich_ip(cur, ip)
                if i < len(candidates) - 1:
                    time.sleep(15)  # respeita o limite de 4 req/min do VirusTotal (plano gratuito)
        except psycopg2.Error as exc:
            print(f"erro de banco, reconectando: {exc}", flush=True)
            conn.rollback()
            conn = connect_db()
            cur = conn.cursor()

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
