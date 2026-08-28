"""
Transforma achado bruto de varredura em vulnerabilidade rastreada.

O scanner grava cada achado em raw_events, que e uma foto do momento: nao tem
estado, nao tem historico, e a mesma coisa aparece de novo a cada varredura.
Este modulo le esses eventos e faz upsert em vulnerabilities usando
(asset, signature) como chave.

Consequencias praticas disso:
- o mesmo achado voltando so atualiza last_seen, nao vira linha nova;
- achado marcado como corrigido que reaparece e reaberto automaticamente e
  conta no reopened_count, entao nao da pra fechar chamado sem consertar.
"""

import json

# Servico exposto sem estar atras de autenticacao forte. Banco de dados no meio
# da rede e o caso mais comum e mais caro, entao pesa mais.
SENSITIVE_PORTS = {
    1433: ("SQL Server", "high"),
    3306: ("MySQL", "high"),
    5432: ("PostgreSQL", "high"),
    5984: ("CouchDB", "high"),
    6379: ("Redis", "high"),
    9200: ("Elasticsearch", "high"),
    11211: ("Memcached", "high"),
    27017: ("MongoDB", "high"),
}

# Acesso administrativo remoto. Alto quando o protocolo e em texto claro.
ADMIN_PORTS = {
    21: ("FTP", "medium"),
    22: ("SSH", "medium"),
    23: ("Telnet", "high"),
    3389: ("RDP", "high"),
    5900: ("VNC", "high"),
}

WEB_PORTS = {80, 443, 8000, 8080, 8443, 3000}

# Quando a fonte nao informa CVSS, deriva da severidade pra tela nao ficar com
# coluna vazia. Valor no meio da faixa de cada nivel.
CVSS_BY_SEVERITY = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 0.0}

VALID_SEVERITIES = set(CVSS_BY_SEVERITY)


def normalize_severity(value: str | None) -> str:
    value = (value or "").strip().lower()
    if value in VALID_SEVERITIES:
        return value
    # nuclei tambem devolve 'unknown' em alguns templates.
    return "info"


def from_nmap(event: dict) -> dict | None:
    """Porta aberta vira vulnerabilidade quando o servico exposto tem risco.
    Porta web aberta nao e achado por si so, e o esperado."""
    payload = event["payload"]
    port = payload.get("port")
    protocol = payload.get("protocol") or "tcp"
    service = payload.get("service")
    product = payload.get("product")
    version = payload.get("version")

    if port is None:
        return None

    label, severity = SENSITIVE_PORTS.get(port) or ADMIN_PORTS.get(port) or (None, None)
    if label is None:
        if port in WEB_PORTS:
            label, severity = (service or "HTTP"), "info"
        else:
            label, severity = (service or f"porta {port}"), "low"

    # O nmap ja devolve o produto por extenso ("PostgreSQL DB 9.6.0 or later"),
    # que costuma comecar com o mesmo nome do rotulo. Repetir os dois gera
    # "PostgreSQL PostgreSQL DB 9.6.0 exposto na porta 5432".
    banner = " ".join(p for p in (product, version) if p)
    if banner and label.lower() in banner.lower():
        title = f"{banner} exposto na porta {port}"
    elif banner:
        title = f"{label} {banner} exposto na porta {port}"
    else:
        title = f"{label} exposto na porta {port}"

    if severity == "high":
        description = (
            f"O servico {label} responde na porta {port}/{protocol} e esta alcancavel pela rede. "
            "Servico desse tipo exposto e caminho direto pra acesso a dado, e normalmente nao "
            "deveria estar acessivel fora da propria maquina."
        )
    elif severity == "medium":
        description = (
            f"Acesso administrativo remoto por {label} na porta {port}/{protocol}. "
            "Vale confirmar se a exposicao e intencional e se ha limite de origem."
        )
    else:
        description = f"Servico {label} respondendo na porta {port}/{protocol}."

    return {
        # A assinatura nao carrega versao de proposito: subir a versao do
        # servico nao pode criar uma vulnerabilidade nova, tem que atualizar
        # a que ja existe.
        "signature": f"nmap:{port}/{protocol}",
        "asset_type": "rede",
        "title": title,
        "description": description,
        "severity": severity,
        "cvss": CVSS_BY_SEVERITY[severity],
        "cve": None,
        "port": port,
        "service": service,
        "source": "nmap",
        "evidence": payload,
    }


def from_nuclei(event: dict) -> dict | None:
    payload = event["payload"]
    template = payload.get("template_id")
    if not template:
        return None

    severity = normalize_severity(payload.get("severity"))
    cve = payload.get("cve")
    if isinstance(cve, list):
        cve = cve[0] if cve else None

    cvss = payload.get("cvss")
    if not isinstance(cvss, (int, float)):
        cvss = CVSS_BY_SEVERITY[severity]

    matched = payload.get("matched_at") or ""
    # O caminho entra na assinatura porque o mesmo template achando coisa em
    # duas rotas diferentes sao dois achados distintos, nao um.
    path = ""
    if "://" in matched:
        rest = matched.split("://", 1)[1]
        path = "/" + rest.split("/", 1)[1] if "/" in rest else ""

    return {
        "signature": f"nuclei:{template}{path}",
        "asset_type": "web",
        "title": payload.get("name") or template,
        "description": payload.get("description"),
        "severity": severity,
        "cvss": cvss,
        "cve": cve,
        "port": None,
        "service": None,
        "source": "nuclei",
        "evidence": payload,
    }


MAPPERS = {
    "scanner.nmap.port_open": from_nmap,
    "scanner.nuclei.finding": from_nuclei,
}


SELECT_EXISTING = """
    SELECT id, status, reopened_count
    FROM vulnerabilities WHERE asset = %s AND signature = %s
"""

INSERT_VULN = """
    INSERT INTO vulnerabilities (
        asset, asset_type, signature, title, description, severity, cvss, cve,
        port, service, evidence, source, status, first_seen, last_seen,
        source_event_id
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'open', %s, %s, %s)
"""

UPDATE_VULN = """
    UPDATE vulnerabilities SET
        title = %s, description = %s, severity = %s, cvss = %s, cve = %s,
        port = %s, service = %s, evidence = %s, last_seen = %s,
        source_event_id = %s, status = %s, reopened_count = %s,
        resolved_at = CASE WHEN %s = 'open' THEN NULL ELSE resolved_at END
    WHERE id = %s
"""


def get_checkpoint(cur) -> int:
    cur.execute("SELECT last_event_id FROM vuln_checkpoint WHERE id = 1")
    row = cur.fetchone()
    return row[0] if row else 0


def save_checkpoint(cur, last_event_id: int) -> None:
    cur.execute("UPDATE vuln_checkpoint SET last_event_id = %s WHERE id = 1", (last_event_id,))


def normalize_new_events(cur) -> dict:
    """Consome os raw_events de scanner que chegaram desde o ultimo ciclo.
    Devolve o que mudou, pra virar o resumo da varredura na tela."""
    last_id = get_checkpoint(cur)
    cur.execute(
        """
        SELECT id, ts, host, event_type, payload
        FROM raw_events
        WHERE id > %s AND source = 'scanner'
        ORDER BY id
        """,
        (last_id,),
    )
    rows = cur.fetchall()
    # `ativos` guarda quem foi realmente tocado nesta rodada. Sem isso, a conta
    # de "sumiram" acusaria como sumido tudo que nao foi reavaliado, inclusive
    # ativo que nem estava no escopo da varredura.
    stats = {"achados": 0, "novos": 0, "reabertos": 0, "atualizados": 0, "ativos": []}
    if not rows:
        return stats
    touched: set[str] = set()

    for event_id, ts, host, event_type, payload in rows:
        last_id = event_id
        mapper = MAPPERS.get(event_type)
        if mapper is None:
            continue

        finding = mapper({"payload": payload})
        if finding is None:
            continue

        asset = host or "desconhecido"
        touched.add(asset)
        stats["achados"] += 1

        cur.execute(SELECT_EXISTING, (asset, finding["signature"]))
        existing = cur.fetchone()
        evidence = json.dumps(finding["evidence"])

        if existing is None:
            cur.execute(
                INSERT_VULN,
                (
                    asset, finding["asset_type"], finding["signature"], finding["title"],
                    finding["description"], finding["severity"], finding["cvss"], finding["cve"],
                    finding["port"], finding["service"], evidence, finding["source"],
                    ts, ts, event_id,
                ),
            )
            stats["novos"] += 1
            continue

        vuln_id, status, reopened = existing
        # Reabre o que tinha sido dado como corrigido e voltou a aparecer.
        # Risco aceito nao reabre: alguem decidiu conviver com aquilo.
        if status == "remediated":
            status, reopened = "open", reopened + 1
            stats["reabertos"] += 1
        else:
            stats["atualizados"] += 1

        cur.execute(
            UPDATE_VULN,
            (
                finding["title"], finding["description"], finding["severity"], finding["cvss"],
                finding["cve"], finding["port"], finding["service"], evidence, ts,
                event_id, status, reopened, status, vuln_id,
            ),
        )

    save_checkpoint(cur, last_id)
    stats["ativos"] = sorted(touched)
    return stats


def count_disappeared(cur, since, assets: list[str]) -> int:
    """Vulnerabilidade aberta de um ativo que FOI reavaliado nesta varredura e
    mesmo assim nao apareceu de novo.

    Restringir aos ativos tocados e o que faz a conta significar alguma coisa:
    sem isso, todo achado de um alvo fora do escopo da rodada apareceria como
    sumido, e o numero so cresceria.

    Nao fecho sozinho de proposito: sumir do scan tambem acontece quando o
    alvo esta fora do ar, e fechar por isso seria mentir que foi corrigido."""
    if not assets:
        return 0
    cur.execute(
        """
        SELECT count(*) FROM vulnerabilities
        WHERE status IN ('open','in_progress') AND asset = ANY(%s) AND last_seen < %s
        """,
        (assets, since),
    )
    return cur.fetchone()[0]
