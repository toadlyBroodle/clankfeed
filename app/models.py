from datetime import datetime, timezone

from sqlalchemy import Column, String, Integer, Float, Text, DateTime, Index

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
    value_sats = Column(Integer, default=0)
    value_usd = Column(Text, default="0")

    __table_args__ = (
        Index("ix_nostr_events_pubkey", "pubkey"),
        Index("ix_nostr_events_kind", "kind"),
        Index("ix_nostr_events_created_at", "created_at"),
        Index("ix_nostr_events_kind_created_at", "kind", "created_at"),
        Index("ix_nostr_events_value_sats", "value_sats"),
    )


class Account(Base):
    __tablename__ = "accounts"

    id = Column(String(64), primary_key=True)  # API key
    pubkey = Column(String(64), nullable=True, unique=True)  # linked external Nostr pubkey
    nostr_privkey = Column(Text, nullable=True)  # encrypted secp256k1 private key
    nostr_pubkey = Column(String(64), nullable=True)  # derived x-only public key (hex)
    balance_sats = Column(Integer, default=0)
    balance_usd = Column(Text, default="0")
    created_at = Column(DateTime, default=lambda: datetime.utcnow())

    __table_args__ = (
        Index("ix_accounts_pubkey", "pubkey"),
    )


class Vote(Base):
    __tablename__ = "votes"

    id = Column(String(64), primary_key=True)  # random hex
    event_id = Column(String(64), nullable=False)
    pubkey = Column(String(64), nullable=False)
    direction = Column(Integer, nullable=False)  # +1 or -1
    amount_sats = Column(Integer, default=0)
    amount_usd = Column(Text, default="0")
    payment_id = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.utcnow())

    __table_args__ = (
        Index("ix_votes_event_id", "event_id"),
        Index("ix_votes_event_pubkey", "event_id", "pubkey"),
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
    amount_sats = Column(Integer, default=0)
    amount_usd = Column(Text, default="0")
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    expires_at = Column(DateTime, nullable=False)

    __table_args__ = (
        Index("ix_pending_events_payment_hash", "payment_hash"),
    )
