"""
Illustrative test: ensure password analysis works for free users.
Requires test client and user fixture.
"""

def test_password_analysis_free_user(client, free_user_token):
    resp = client.post(
        "/analyze/",
        headers={"Authorization": f"Bearer {free_user_token}"},
        json={
            "input": "TestPassword123!",
            "analysis_type": "password"
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "risk_score" in body
    assert "risk_level" in body
