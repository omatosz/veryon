"""
Gera um relatorio SOC (HTML + PDF) a partir dos dados em raw_events/alerts/
ip_enrichment, cobrindo os ultimos N dias. Roda sob demanda:

    docker compose run --rm reports --days 7
"""

import argparse
import os
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

DB_DSN = os.environ["DATABASE_URL"]
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/app/output")

LEVEL_ORDER_SQL = """
    CASE level
        WHEN 'critical' THEN 0
        WHEN 'high' THEN 1
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 3
        ELSE 4
    END
"""


def fetch_report_data(cur, days):
    cur.execute("SELECT count(*) AS n FROM raw_events WHERE ts >= now() - make_interval(days => %s)", (days,))
    total_events = cur.fetchone()["n"]

    cur.execute("SELECT count(*) AS n FROM alerts WHERE ts >= now() - make_interval(days => %s)", (days,))
    total_alerts = cur.fetchone()["n"]

    cur.execute(
        "SELECT level, count(*) AS n FROM alerts WHERE ts >= now() - make_interval(days => %s) GROUP BY level",
        (days,),
    )
    alerts_by_level = {row["level"]: row["n"] for row in cur.fetchall()}

    cur.execute(
        f"""
        SELECT ts, title, level, mitre_technique, source_host, source_ip
        FROM alerts
        WHERE ts >= now() - make_interval(days => %s)
        ORDER BY {LEVEL_ORDER_SQL}, ts DESC
        LIMIT 100
        """,
        (days,),
    )
    alerts = cur.fetchall()

    cur.execute(
        """
        SELECT mitre_technique AS technique, count(*) AS n
        FROM alerts
        WHERE ts >= now() - make_interval(days => %s) AND mitre_technique IS NOT NULL
        GROUP BY mitre_technique
        ORDER BY n DESC
        """,
        (days,),
    )
    mitre_summary = [{"technique": r["technique"], "count": r["n"]} for r in cur.fetchall()]

    cur.execute(
        """
        SELECT re.src_ip, count(*) AS n, ie.abuseipdb_score, ie.virustotal_malicious, ie.abuseipdb_country
        FROM raw_events re
        LEFT JOIN ip_enrichment ie ON ie.ip = re.src_ip
        WHERE re.ts >= now() - make_interval(days => %s) AND re.src_ip IS NOT NULL
        GROUP BY re.src_ip, ie.abuseipdb_score, ie.virustotal_malicious, ie.abuseipdb_country
        ORDER BY n DESC
        LIMIT 10
        """,
        (days,),
    )
    top_ips = [
        {
            "src_ip": r["src_ip"],
            "count": r["n"],
            "abuseipdb_score": r["abuseipdb_score"],
            "virustotal_malicious": r["virustotal_malicious"],
            "abuseipdb_country": r["abuseipdb_country"],
        }
        for r in cur.fetchall()
    ]

    cur.execute(
        """
        SELECT ts, host, payload->>'severity' AS severity, payload->>'name' AS name
        FROM raw_events
        WHERE event_type = 'scanner.nuclei.finding'
          AND ts >= now() - make_interval(days => %s)
        ORDER BY ts DESC
        LIMIT 50
        """,
        (days,),
    )
    nuclei_findings = cur.fetchall()

    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "alerts_by_level": alerts_by_level,
        "alerts": alerts,
        "mitre_summary": mitre_summary,
        "top_ips": top_ips,
        "nuclei_findings": nuclei_findings,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=int(os.environ.get("REPORT_DAYS", "7")))
    args = parser.parse_args()

    conn = psycopg2.connect(DB_DSN)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    data = fetch_report_data(cur, args.days)

    now = datetime.now(timezone.utc)
    data["period_label"] = f"últimos {args.days} dias (até {now.strftime('%Y-%m-%d %H:%M UTC')})"
    data["generated_at"] = now.strftime("%Y-%m-%d %H:%M UTC")

    env = Environment(loader=FileSystemLoader(os.path.dirname(__file__)))
    html_str = env.get_template("template.html").render(**data)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    stamp = now.strftime("%Y%m%d-%H%M%S")
    html_path = os.path.join(OUTPUT_DIR, f"relatorio-soc-{stamp}.html")
    pdf_path = os.path.join(OUTPUT_DIR, f"relatorio-soc-{stamp}.pdf")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_str)
    HTML(string=html_str, base_url=os.path.dirname(__file__)).write_pdf(pdf_path)

    print(f"relatorio gerado: {html_path}", flush=True)
    print(f"relatorio gerado: {pdf_path}", flush=True)
    print(
        f"resumo: {data['total_events']} eventos, {data['total_alerts']} alertas "
        f"({', '.join(f'{k}={v}' for k, v in data['alerts_by_level'].items())})",
        flush=True,
    )


if __name__ == "__main__":
    main()
