import uuid
from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import text

from app.db import SessionLocal
from app.main import app
from app.routes import auth


def _insert_user(db, user_id: str, *, name: str, email: str, phone: str, plan: str = "GO_PRO"):
    db.execute(
        text(
            """
            INSERT INTO users (
                id, name, email, phone, password_hash, auth_provider, plan,
                subscription_status, preferred_language, accepted_terms
            )
            VALUES (
                CAST(:id AS uuid), :name, :email, :phone, :password_hash, 'password', :plan,
                'ACTIVE', 'en', true
            )
            """
        ),
        {
            "id": user_id,
            "name": name,
            "email": email,
            "phone": phone,
            "password_hash": "test-hash",
            "plan": plan,
        },
    )


def test_contacts_invite_route_alias_and_notifications_feed():
    sender_id = str(uuid.uuid4())
    receiver_id = str(uuid.uuid4())
    secure_item_id = str(uuid.uuid4())

    sender = SimpleNamespace(
        id=sender_id,
        name="Sender",
        email="sender@example.com",
        phone="9990011111",
        phone_number="9990011111",
        plan="GO_PRO",
    )
    receiver = SimpleNamespace(
        id=receiver_id,
        name="Receiver",
        email="receiver@example.com",
        phone="9990022222",
        phone_number="9990022222",
        plan="GO_PRO",
    )

    db = SessionLocal()
    try:
        _insert_user(db, sender_id, name="Sender", email="sender@example.com", phone="9990011111")
        _insert_user(db, receiver_id, name="Receiver", email="receiver@example.com", phone="9990022222")
        db.execute(
            text(
                """
                INSERT INTO secure_now_items (
                    id, user_id, type, title, description, status, risk_level, auto_created, created_at
                )
                VALUES (
                    CAST(:id AS uuid), CAST(:user_id AS uuid), 'WEAK_PASSWORD', 'Change password',
                    'Use a stronger password now.', 'PENDING', 'high', true, CURRENT_TIMESTAMP
                )
                """
            ),
            {"id": secure_item_id, "user_id": receiver_id},
        )
        db.commit()

        app.dependency_overrides[auth.get_current_user] = lambda: sender
        app.dependency_overrides[auth.get_current_user_optional] = lambda: sender
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.post(
                "/contacts/invite",
                json={
                    "name": "Receiver",
                    "phone": "9990022222",
                    "relationship": "Sibling",
                    "add_to_family": True,
                },
            )
            assert response.status_code == 200, response.text
            payload = response.json()["data"]
            assert payload["status"] == "invite_sent"

        app.dependency_overrides[auth.get_current_user] = lambda: receiver
        app.dependency_overrides[auth.get_current_user_optional] = lambda: receiver
        with TestClient(app, raise_server_exceptions=False) as client:
            notifications = client.get("/notifications")
            assert notifications.status_code == 200, notifications.text
            body = notifications.json()["data"]
            assert len(body["invites"]) == 1
            assert body["invites"][0]["sender_name"] == "Sender"
            assert len(body["system_events"]) == 1
            assert body["system_events"][0]["title"] == "Change password"
    finally:
        app.dependency_overrides.clear()
        db.execute(text("DELETE FROM secure_now_items WHERE id = CAST(:id AS uuid)"), {"id": secure_item_id})
        db.execute(text("DELETE FROM trusted_contact_invites WHERE sender_user_id = CAST(:uid AS uuid)"), {"uid": sender_id})
        db.execute(text("DELETE FROM users WHERE id = CAST(:sender AS uuid)"), {"sender": sender_id})
        db.execute(text("DELETE FROM users WHERE id = CAST(:receiver AS uuid)"), {"receiver": receiver_id})
        db.commit()
        db.close()
