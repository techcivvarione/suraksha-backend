from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models.qr_models import QrReputation


# SECURE QR START
def get_or_create_reputation(db: Session, qr_hash: str) -> QrReputation:
    """
    Fetch reputation row; create if missing.
    """
    reputation = (
        db.execute(
            select(QrReputation).where(QrReputation.qr_hash == qr_hash).with_for_update()
        ).scalar_one_or_none()
    )
    if reputation:
        return reputation

    db.add(QrReputation(qr_hash=qr_hash))
    db.flush()
    reputation = (
        db.execute(
            select(QrReputation).where(QrReputation.qr_hash == qr_hash).with_for_update()
        ).scalar_one()
    )
    return reputation


def increment_reported(db: Session, qr_hash: str) -> QrReputation:
    """
    Atomic increment of reported_count using SQL update; returns fresh row.
    """
    db.execute(
        update(QrReputation)
        .where(QrReputation.qr_hash == qr_hash)
        .values(reported_count=QrReputation.reported_count + 1)
    )
    db.flush()
    return (
        db.execute(
            select(QrReputation).where(QrReputation.qr_hash == qr_hash).with_for_update()
        ).scalar_one()
    )
# SECURE QR END
