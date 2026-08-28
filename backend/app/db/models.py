from decimal import Decimal

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, Numeric, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class RawEvent(Base):
    __tablename__ = "raw_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[DateTime] = mapped_column(DateTime(timezone=True), primary_key=True, nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False)
    host: Mapped[str | None] = mapped_column(String)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[DateTime] = mapped_column(DateTime(timezone=True), primary_key=True, nullable=False)
    rule_id: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    level: Mapped[str] = mapped_column(String, nullable=False)
    mitre_technique: Mapped[str | None] = mapped_column(String)
    source_event_id: Mapped[int | None] = mapped_column(BigInteger)
    source_event_type: Mapped[str | None] = mapped_column(String)
    source_host: Mapped[str | None] = mapped_column(String)
    source_ip: Mapped[str | None] = mapped_column(String)
    description: Mapped[str | None] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, nullable=False, server_default="open")
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)


class IPEnrichment(Base):
    __tablename__ = "ip_enrichment"

    ip: Mapped[str] = mapped_column(String, primary_key=True)
    checked_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    abuseipdb_score: Mapped[int | None] = mapped_column(Integer)
    abuseipdb_country: Mapped[str | None] = mapped_column(String)
    abuseipdb_isp: Mapped[str | None] = mapped_column(String)
    abuseipdb_total_reports: Mapped[int | None] = mapped_column(Integer)
    virustotal_malicious: Mapped[int | None] = mapped_column(Integer)
    virustotal_total_engines: Mapped[int | None] = mapped_column(Integer)
    virustotal_reputation: Mapped[int | None] = mapped_column(Integer)
    otx_pulse_count: Mapped[int | None] = mapped_column(Integer)
    raw_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String, nullable=False)
    alert_id: Mapped[int | None] = mapped_column(BigInteger)
    reason: Mapped[str | None] = mapped_column(String)
    blocked_by: Mapped[str] = mapped_column(String, nullable=False)
    blocked_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    unblocked_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True))
    unblocked_by: Mapped[str | None] = mapped_column(String)
    # NULL quer dizer bloqueio sem prazo, so sai na mao.
    expires_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String, nullable=False, server_default="manual")
    policy_id: Mapped[int | None] = mapped_column(BigInteger)


class Vulnerability(Base):
    """Achado de varredura com ciclo de vida.

    A chave de deduplicacao e (asset, signature). O normalizador faz upsert por
    ela, entao o mesmo achado numa varredura seguinte atualiza last_seen em vez
    de virar linha nova."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    asset: Mapped[str] = mapped_column(String, nullable=False)
    asset_type: Mapped[str] = mapped_column(String, nullable=False)
    signature: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    cvss: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    cve: Mapped[str | None] = mapped_column(String)
    port: Mapped[int | None] = mapped_column(Integer)
    service: Mapped[str | None] = mapped_column(String)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, server_default="open")
    first_seen: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True))
    updated_by: Mapped[str | None] = mapped_column(String)
    justification: Mapped[str | None] = mapped_column(Text)
    review_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True))
    reopened_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    source_event_id: Mapped[int | None] = mapped_column(BigInteger)


class ScanJob(Base):
    """Pedido de varredura. A tela enfileira, o servico do scanner consome."""

    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    status: Mapped[str] = mapped_column(String, nullable=False, server_default="queued")
    requested_by: Mapped[str] = mapped_column(String, nullable=False)
    targets: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    stats: Mapped[dict | None] = mapped_column(JSONB)


class IPAllowlist(Base):
    """Quem nunca pode ser bloqueado por politica. Bloqueio manual ainda passa,
    mas a API avisa que o alvo esta na lista antes de deixar seguir."""

    __tablename__ = "ip_allowlist"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    cidr: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    reason: Mapped[str | None] = mapped_column(String)
    added_by: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class APIRequest(Base):
    """Uma requisicao de API observada. Vem do proprio Veryon ou do gateway de
    um cliente pelo /ingest/api-logs."""

    __tablename__ = "api_requests"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[DateTime] = mapped_column(DateTime(timezone=True), primary_key=True, nullable=False)
    source: Mapped[str] = mapped_column(String, nullable=False, server_default="self")
    client_ip: Mapped[str | None] = mapped_column(String)
    method: Mapped[str] = mapped_column(String(8), nullable=False)
    path: Mapped[str] = mapped_column(String, nullable=False)
    route: Mapped[str] = mapped_column(String, nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    response_bytes: Mapped[int | None] = mapped_column(Integer)
    user_agent: Mapped[str | None] = mapped_column(String(300))
    query: Mapped[str | None] = mapped_column(String(500))
    flags: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))


class APIEndpoint(Base):
    """Inventario de rotas. Rota que aparece no trafego sem estar declarada
    aqui como documentada e o que o motor chama de API fantasma."""

    __tablename__ = "api_endpoints"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    method: Mapped[str] = mapped_column(String(8), nullable=False)
    route: Mapped[str] = mapped_column(String, nullable=False)
    is_documented: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    is_sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    first_seen: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    request_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    error_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    avg_response_bytes: Mapped[int | None] = mapped_column(Integer)


class PreventionPolicy(Base):
    """Uma regra que o sistema tem permissao de aplicar sozinho.

    kind aponta pra um avaliador conhecido no codigo, nao pra uma linguagem de
    regra generica. Menos flexivel de proposito: regra generica e o caminho
    mais curto pra alguem escrever sem querer algo que bloqueia o parque."""

    __tablename__ = "prevention_policies"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    params: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    action: Mapped[str] = mapped_column(String(24), nullable=False)
    ttl_minutes: Mapped[int | None] = mapped_column(Integer)
    mode: Mapped[str] = mapped_column(String(16), nullable=False, server_default="observe")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    priority: Mapped[int] = mapped_column(Integer, nullable=False, server_default="100")
    cooldown_minutes: Mapped[int] = mapped_column(Integer, nullable=False, server_default="10")
    match_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    action_count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    last_match_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True))
    updated_by: Mapped[str | None] = mapped_column(String)


class PreventionAction(Base):
    """Tudo o que a prevencao fez ou teria feito, e por que.

    Escreve linha inclusive quando a politica estava so observando e inclusive
    quando um trilho de seguranca impediu. Acao automatica invisivel e o que
    transforma um incidente pequeno em investigacao longa."""

    __tablename__ = "prevention_actions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    policy_id: Mapped[int | None] = mapped_column(BigInteger)
    policy_code: Mapped[str | None] = mapped_column(String(32))
    action_type: Mapped[str] = mapped_column(String(24), nullable=False)
    target: Mapped[str] = mapped_column(String, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    rail: Mapped[str | None] = mapped_column(String(48))
    blocked_ip_id: Mapped[int | None] = mapped_column(BigInteger)
    source_kind: Mapped[str | None] = mapped_column(String(24))
    source_id: Mapped[int | None] = mapped_column(BigInteger)
    undone_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True))
    undone_by: Mapped[str | None] = mapped_column(String)
    created_by: Mapped[str] = mapped_column(String, nullable=False, server_default="veryon")


class APIFinding(Base):
    """Resultado da analise, um por chamador. O motor faz upsert por client_ip
    a cada ciclo em vez de empilhar linha."""

    __tablename__ = "api_findings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    client_ip: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    signals: Mapped[list] = mapped_column(JSONB, nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    distinct_routes: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    top_routes: Mapped[list | None] = mapped_column(JSONB)
    window_start: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    first_seen: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, server_default="open")
    updated_by: Mapped[str | None] = mapped_column(String)
    note: Mapped[str | None] = mapped_column(Text)
    muted_until: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True))
    alert_id: Mapped[int | None] = mapped_column(BigInteger)
