from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models.scam_report import ScamReport
from app.services.scam_network.abuse_guard import ScamNetworkAbuseError, enforce_report_limits, suppress_duplicate_report
from app.services.scam_network.aggregation_service import update_aggregations
from app.services.scam_network.normalization import normalize_payment_handle, normalize_phone_number, normalize_url


@dataclass
class ScamReportResult:
    report: ScamReport
    duplicate: bool


class ScamReportService:
    def create_report(self, db: Session, *, current_user, payload, client_ip: str | None, user_agent: str | None) -> ScamReportResult:
        normalized_phone, display_phone = normalize_phone_number(payload.scam_phone_number)
        normalized_url = normalize_url(payload.phishing_url)
        normalized_payment_handle = normalize_payment_handle(payload.payment_handle)
        entity_key = normalized_phone or normalized_url or normalized_payment_handle or payload.category
        report_hash = self._build_report_hash(
            user_id=str(current_user.id),
            report_type=payload.report_type,
            entity_key=entity_key,
            category=payload.category,
        )

        enforce_report_limits(db, user_id=str(current_user.id), ip=client_ip, entity_key=entity_key)
        duplicate = suppress_duplicate_report(report_hash, user_id=str(current_user.id))

        report = ScamReport(
            user_id=current_user.id,
            report_type=payload.report_type,
            category=payload.category,
            scam_phone_number=display_phone or payload.scam_phone_number,
            normalized_phone_number=normalized_phone,
            phishing_url=payload.phishing_url,
            normalized_url=normalized_url,
            payment_handle=payload.payment_handle,
            payment_provider=payload.payment_provider,
            scam_description=payload.scam_description,
            report_hash=report_hash,
            latitude=payload.geo_location.lat if payload.geo_location else None,
            longitude=payload.geo_location.lng if payload.geo_location else None,
            city=payload.region.city if payload.region else None,
            state=payload.region.state if payload.region else None,
            country=payload.region.country if payload.region else None,
            status='DUPLICATE' if duplicate else 'REPORTED',
            visibility_status='SUSPICIOUS',
        )
        db.add(report)
        db.flush()
        if not duplicate:
            update_aggregations(db, report)
        else:
            db.commit()
        return ScamReportResult(report=report, duplicate=duplicate)

    def _build_report_hash(self, *, user_id: str, report_type: str, entity_key: str, category: str) -> str:
        payload = f'{user_id}:{report_type}:{entity_key}:{category}'
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()
