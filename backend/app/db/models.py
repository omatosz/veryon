from sqlalchemy import BigInteger, DateTime, Integer, String, func
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
