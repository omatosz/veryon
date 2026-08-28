from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    source: str
    host: str | None
    event_type: str
    src_ip: str | None
    payload: dict


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    rule_id: str
    title: str
    level: str
    mitre_technique: str | None
    source_event_id: int | None
    source_event_type: str | None
    source_host: str | None
    source_ip: str | None
    description: str | None
    status: str
    payload: dict


class AlertStatusUpdate(BaseModel):
    status: str


class EnrichmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip: str
    checked_at: datetime
    abuseipdb_score: int | None
    abuseipdb_country: str | None
    abuseipdb_isp: str | None
    abuseipdb_total_reports: int | None
    virustotal_malicious: int | None
    virustotal_total_engines: int | None
    virustotal_reputation: int | None
    otx_pulse_count: int | None


class BlockedIPOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip: str
    alert_id: int | None
    reason: str | None
    blocked_by: str
    blocked_at: datetime
    unblocked_at: datetime | None
    unblocked_by: str | None
    expires_at: datetime | None
    source: str
    policy_id: int | None


class BlockIPIn(BaseModel):
    """Bloqueio manual, digitando o alvo na tela de Lista de IPs."""

    ip: str
    reason: str = Field(min_length=3, max_length=200)
    # Sem prazo o bloqueio so sai na mao. Teto de 30 dias porque bloqueio
    # eterno com prazo nao faz sentido: ou e permanente, ou tem data.
    ttl_minutes: int | None = Field(default=None, ge=1, le=60 * 24 * 30)


class AllowlistOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    cidr: str
    reason: str | None
    added_by: str
    created_at: datetime


class AllowlistIn(BaseModel):
    cidr: str
    reason: str | None = Field(default=None, max_length=200)


VULN_STATUSES = ("open", "in_progress", "remediated", "accepted_risk")
SEVERITIES = ("critical", "high", "medium", "low", "info")


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset: str
    asset_type: str
    signature: str
    title: str
    description: str | None
    severity: str
    cvss: float | None
    cve: str | None
    port: int | None
    service: str | None
    evidence: dict
    source: str
    status: str
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None
    updated_by: str | None
    justification: str | None
    review_at: datetime | None
    reopened_count: int
    source_event_id: int | None


class VulnerabilityUpdate(BaseModel):
    status: Literal["open", "in_progress", "remediated", "accepted_risk"]
    justification: str | None = Field(default=None, max_length=1000)
    review_at: datetime | None = None

    @model_validator(mode="after")
    def exigir_justificativa(self) -> "VulnerabilityUpdate":
        # Aceitar risco sem justificativa escrita e sem data pra revisitar e o
        # jeito mais facil de nunca corrigir nada. A API nao deixa.
        if self.status == "accepted_risk":
            if not (self.justification or "").strip():
                raise ValueError("aceitar o risco exige justificativa")
            if self.review_at is None:
                raise ValueError("aceitar o risco exige uma data de revisao")
        return self


class ScanJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: str
    requested_by: str
    targets: dict | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    stats: dict | None


class VulnSummaryOut(BaseModel):
    by_severity: dict[str, int]
    by_status: dict[str, int]
    total_open: int
    # 0 a 100, ponderado pela severidade do que esta em aberto.
    risk_score: int
    last_scan: ScanJobOut | None


class SummaryOut(BaseModel):
    total_events: int
    total_alerts: int
    events_by_source: dict[str, int]
    alerts_by_level: dict[str, int]
    top_src_ips: list[dict]


class SeriesPoint(BaseModel):
    """Uma linha da serie temporal. A tela e quem empilha e filtra."""

    ts: str
    category: str
    level: str
    count: int


class GeoPoint(BaseModel):
    country: str
    events: int
    ips: int
    blocked: int
    worst_score: int


class GeoSummaryOut(BaseModel):
    points: list[GeoPoint]
    # Trafego de dentro de casa e de IP publico nao identificado sao contados
    # separado. Juntar os dois num balde de "desconhecido" esconderia que o
    # primeiro nao tem pais nenhum pra descobrir.
    internal_events: int
    unidentified_events: int
    total_ips: int


# --- Analise de API ---------------------------------------------------------


class APIFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    client_ip: str
    score: int
    severity: str
    signals: list[dict]
    request_count: int
    distinct_routes: int
    top_routes: list[dict] | None
    window_start: datetime
    window_end: datetime
    first_seen: datetime
    last_seen: datetime
    status: str
    updated_by: str | None
    note: str | None
    muted_until: datetime | None
    alert_id: int | None


class APIFindingUpdate(BaseModel):
    status: Literal["open", "investigating", "benign", "escalated", "resolved"]
    note: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def exigir_nota(self) -> "APIFindingUpdate":
        # Marcar como benigno silencia o chamador por horas. Se ninguem escreve
        # o motivo, o proximo analista nao tem como saber se foi analise ou
        # preguica.
        if self.status == "benign" and not (self.note or "").strip():
            raise ValueError("marcar como benigno exige uma nota explicando o motivo")
        return self


class APIEndpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    method: str
    route: str
    is_documented: bool
    is_sensitive: bool
    first_seen: datetime
    last_seen: datetime
    request_count: int
    error_count: int
    avg_response_bytes: int | None


class APIRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    source: str
    client_ip: str | None
    method: str
    path: str
    route: str
    status_code: int | None
    duration_ms: int | None
    response_bytes: int | None
    user_agent: str | None
    query: str | None
    flags: dict


class APISummaryOut(BaseModel):
    window_minutes: int
    total_requests: int
    error_rate: int
    distinct_callers: int
    open_findings: int
    critical_findings: int
    shadow_endpoints: int
    documented_endpoints: int
    top_findings: list[APIFindingOut]
    queue: dict


class IngestedRequest(BaseModel):
    """Uma requisicao vinda do gateway de um cliente.

    Campos minimos de proposito: qualquer log de acesso tem metodo, caminho e
    status. Quanto mais o cliente mandar, melhor a analise, mas com esses tres
    ja da pra pontuar."""

    method: str = Field(max_length=8)
    path: str = Field(max_length=300)
    status_code: int | None = Field(default=None, ge=100, le=599)
    client_ip: str | None = None
    ts: datetime | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    response_bytes: int | None = Field(default=None, ge=0)
    user_agent: str | None = Field(default=None, max_length=300)
    query: str | None = Field(default=None, max_length=500)
    # Corpo so e usado pra procurar padrao de injecao e nao fica guardado.
    body: str | None = Field(default=None, max_length=4000)


class IngestBatch(BaseModel):
    requests: list[IngestedRequest] = Field(min_length=1, max_length=500)


class IngestResult(BaseModel):
    aceitas: int
    descartadas: int


# --- Prevencao de ameaca ----------------------------------------------------


class PolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    code: str
    name: str
    description: str
    kind: str
    params: dict
    action: str
    ttl_minutes: int | None
    mode: str
    enabled: bool
    priority: int
    cooldown_minutes: int
    match_count: int
    action_count: int
    last_match_at: datetime | None
    updated_at: datetime | None
    updated_by: str | None


class PolicyUpdate(BaseModel):
    mode: Literal["observe", "enforce"] | None = None
    enabled: bool | None = None
    ttl_minutes: int | None = Field(default=None, ge=1, le=60 * 24 * 30)
    cooldown_minutes: int | None = Field(default=None, ge=1, le=60 * 24)

    @model_validator(mode="after")
    def exigir_prazo_pra_agir(self) -> "PolicyUpdate":
        # Trilho 4 tambem na porta de entrada: ligar uma politica de bloqueio
        # zerando o prazo faria ela nunca agir e ninguem entenderia por que.
        if self.mode == "enforce" and self.ttl_minutes is not None and self.ttl_minutes < 1:
            raise ValueError("politica de bloqueio precisa de prazo pra entrar em vigor")
        return self


class PreventionActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    policy_id: int | None
    policy_code: str | None
    action_type: str
    target: str
    reason: str
    evidence: dict
    mode: str
    status: str
    rail: str | None
    blocked_ip_id: int | None
    source_kind: str | None
    source_id: int | None
    undone_at: datetime | None
    undone_by: str | None
    created_by: str


class SimulatedCase(BaseModel):
    target: str
    reason: str
    acao: str
    seria_segurado: str | None


class SimulationOut(BaseModel):
    simulacao: list[SimulatedCase]
    total: int


class QueueItem(BaseModel):
    """Item da fila critica. Vem de tres origens diferentes e sai com o mesmo
    formato, pra tela nao precisar de tres listas separadas."""

    kind: Literal["alert", "api_finding", "vulnerability"]
    id: int
    title: str
    severity: str
    target: str | None
    ts: datetime
    status: str
    detail: str | None


class PreventionSummaryOut(BaseModel):
    policies_total: int
    policies_enforcing: int
    policies_observing: int
    actions_24h: int
    applied_24h: int
    held_24h: int
    blocks_last_hour: int
    blocks_ceiling: int
    queue_size: int
