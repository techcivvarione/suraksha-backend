from app.routes import scam_radar



def test_radar_live_is_public(client, monkeypatch):
    monkeypatch.setattr(
        scam_radar,
        "_fetch_live_radar_events",
        lambda limit: [{"lat": 17.39, "lng": 78.48, "category": "otp_fraud", "source": "scan"}],
    )

    response = client.get("/scam/radar/live")

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert body["events"][0]["source"] == "scan"
    assert "timestamp" in body



def test_radar_live_limit_validation(client):
    assert client.get("/scam/radar/live?limit=501").status_code == 422
    assert client.get("/scam/radar/live?limit=abc").status_code == 422



def test_radar_live_uses_cache(client, monkeypatch):
    calls = {"count": 0}

    def fake_fetch(limit):
        calls["count"] += 1
        return [{"lat": 17.39, "lng": 78.48, "category": "otp_fraud", "source": "scan"}]

    monkeypatch.setattr(scam_radar, "_fetch_live_radar_events", fake_fetch)

    first = client.get("/scam/radar/live?limit=123")
    second = client.get("/scam/radar/live?limit=123")

    assert first.status_code == 200
    assert second.status_code == 200
    assert calls["count"] == 1
    assert first.json() == second.json()



def test_radar_live_rate_limit_enforced(client, monkeypatch):
    monkeypatch.setattr(scam_radar, "_fetch_live_radar_events", lambda limit: [])

    last_response = None
    for _ in range(61):
        last_response = client.get("/scam/radar/live")

    assert last_response is not None
    assert last_response.status_code == 429
