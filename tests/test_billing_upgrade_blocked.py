def test_billing_upgrade_is_blocked(client, auth_token):
    response = client.post(
        "/billing/upgrade",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"plan": "GO_PRO"},
    )

    assert response.status_code == 403
    body = response.json()
    assert body["detail"]["error"] == "DIRECT_UPGRADE_DISABLED"
