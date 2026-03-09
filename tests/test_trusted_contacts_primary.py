"""
These are illustrative unit tests; they assume a transactional test DB and fixtures
for user creation and Redis.
"""
import uuid

import pytest
from fastapi import HTTPException

from app.routes.trusted_contacts import set_primary_contact


def test_first_contact_auto_primary(db_session, auth_user, client):
    resp = client.post(
        "/contacts/trusted/",
        json={"name": "A", "email": "a@example.com"},
        headers={"Authorization": f"Bearer {auth_user.token}"},
    )
    assert resp.status_code == 200
    data = client.get(
        "/contacts/trusted/",
        headers={"Authorization": f"Bearer {auth_user.token}"},
    ).json()["data"]
    assert any(item["is_primary"] for item in data)


def test_switch_primary(db_session, auth_user, client):
    # assumes two contacts exist
    contacts = client.get(
        "/contacts/trusted/",
        headers={"Authorization": f"Bearer {auth_user.token}"},
    ).json()["data"]
    target = contacts[1]["id"]
    resp = client.patch(
        f"/contacts/trusted/{target}/set-primary",
        headers={"Authorization": f"Bearer {auth_user.token}"},
    )
    assert resp.status_code == 200
    data = client.get(
        "/contacts/trusted/",
        headers={"Authorization": f"Bearer {auth_user.token}"},
    ).json()["data"]
    primaries = [c for c in data if c["is_primary"]]
    assert len(primaries) == 1 and primaries[0]["id"] == target
