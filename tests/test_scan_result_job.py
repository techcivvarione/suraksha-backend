import io


def test_scan_result_returns_pending_job(client, auth_token, monkeypatch):
    monkeypatch.setattr("app.routes.scan_reality_image.upload_file", lambda file_bytes, filename: f"r2/{filename}")
    payload = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    create_response = client.post(
        "/scan/reality/image",
        headers={"Authorization": f"Bearer {auth_token}"},
        files={"file": ("test.png", io.BytesIO(payload), "image/png")},
    )

    assert create_response.status_code == 200
    job_id = create_response.json()["job_id"]

    result_response = client.get(
        f"/scan/result/{job_id}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )

    assert result_response.status_code == 200
    assert result_response.json() == {
        "status": "pending",
        "result": None,
    }
