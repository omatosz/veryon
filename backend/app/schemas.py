from datetime import datetime

from pydantic import BaseModel, ConfigDict


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


class SummaryOut(BaseModel):
    total_events: int
    total_alerts: int
    events_by_source: dict[str, int]
    alerts_by_level: dict[str, int]
    top_src_ips: list[dict]
