from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID

from app.db import Base


class QrReputation(Base):
    __tablename__ = "qr_reputations"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    qr_hash = Column(String(256), nullable=False, unique=True, index=True)
    reported_count = Column(Integer, nullable=False, server_default=text("0"))
    is_flagged = Column(Boolean, nullable=False, server_default=text("false"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class QrScanLog(Base):
    __tablename__ = "qr_scan_logs"
    __table_args__ = (
        Index("ix_qr_scan_logs_user_id_created_at", "user_id", "created_at"),
    )

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    qr_hash = Column(String(256), nullable=False, index=True)
    vpa = Column(String(255), nullable=False)
    is_business = Column(Boolean, nullable=False, server_default=text("false"))
    scam_flag = Column(Boolean, nullable=False, server_default=text("false"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class QrReport(Base):
    __tablename__ = "qr_reports"
    __table_args__ = (
        UniqueConstraint("user_id", "qr_hash", name="uq_qr_reports_user_id_qr_hash"),
        Index("ix_qr_reports_qr_hash_created_at", "qr_hash", "created_at"),
    )

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    qr_hash = Column(String(256), nullable=False, index=True)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
