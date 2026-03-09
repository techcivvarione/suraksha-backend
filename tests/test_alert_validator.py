import pytest
from fastapi import HTTPException

from app.services.alert_validator import validate_request_payload


def test_reject_low_risk():
    with pytest.raises(HTTPException):
        validate_request_payload(
            {
                "analysis_type": "VIDEO",
                "risk_level": "LOW",
                "risk_score": 10,
                "media_hash": "a" * 64,
            }
        )


def test_accept_high_risk():
    validate_request_payload(
        {
            "analysis_type": "AUDIO",
            "risk_level": "HIGH",
            "risk_score": 80,
            "media_hash": "b" * 64,
        }
    )
