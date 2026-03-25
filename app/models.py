from datetime import datetime, timezone

from sqlalchemy import Column, String, Integer, Text, DateTime, Index

from app.database import Base


class NostrEvent(Base):
    __tablename__ = "nostr_events"

    id = Column(String(64), primary_key=True)  # 32-byte hex SHA256
    pubkey = Column(String(64), nullable=False)
    created_at = Column(Integer, nullable=False)
    kind = Column(Integer, nullable=False)
    tags = Column(Text, nullable=False)  # JSON-serialized
    content = Column(Text, nullable=False)
    sig = Column(String(128), nullable=False)  # 64-byte hex Schnorr sig
    stored_at = Column(DateTime, default=lambda: datetime.utcnow())

    __table_args__ = (
        Index("ix_nostr_events_pubkey", "pubkey"),
        Index("ix_nostr_events_kind", "kind"),
        Index("ix_nostr_events_created_at", "created_at"),
        Index("ix_nostr_events_kind_created_at", "kind", "created_at"),
    )


class ConsumedPayment(Base):
    __tablename__ = "consumed_payments"

    payment_hash = Column(String(64), primary_key=True)
    consumed_at = Column(DateTime, default=lambda: datetime.utcnow())


class PendingEvent(Base):
    __tablename__ = "pending_events"

    token = Column(String(64), primary_key=True)  # random hex
    event_json = Column(Text, nullable=False)
    payment_hash = Column(String(64), nullable=False, default="")
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    expires_at = Column(DateTime, nullable=False)

    __table_args__ = (
        Index("ix_pending_events_payment_hash", "payment_hash"),
    )
