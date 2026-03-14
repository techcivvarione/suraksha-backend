from app.services.redis_store import distributed_lock
from app.services.threat_intel_service import _dedupe_events, _normalize_event



def test_distributed_lock_is_exclusive(redis_mock):
    with distributed_lock("worker:test", 30) as first:
        assert first is True
        with distributed_lock("worker:test", 30) as second:
            assert second is False


def test_normalized_threat_events_are_deduplicated():
    event_one = _normalize_event(12.3456, 78.9012, "botnet", 4, 5, "abuseipdb", "1.1.1.1")
    event_two = _normalize_event(12.3456, 78.9012, "botnet", 4, 5, "abuseipdb", "1.1.1.1")
    deduped = _dedupe_events([event_one, event_two])
    assert len(deduped) == 1
    assert deduped[0].id == event_one.id
