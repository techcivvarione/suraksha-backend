from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from app.db import get_db
from app.main import app


class FakeQuery:
    def __init__(self, items):
        self.items = list(items)
        self._offset = 0
        self._limit = None

    def filter(self, *conditions):
        filtered = self.items
        for condition in conditions:
            left = getattr(condition, "left", None)
            right = getattr(condition, "right", None)
            operator = getattr(condition, "operator", None)
            if left is None or right is None or operator is None:
                continue
            key = getattr(left, "key", None)
            if key is None:
                key = getattr(getattr(left, "clause_expr", None), "element", None)
                key = getattr(key, "clauses", [None])[0]
                key = getattr(getattr(key, "element", key), "key", None)
            value = getattr(right, "value", right)
            if key == "category":
                if isinstance(value, (list, tuple, set)):
                    allowed = {str(entry).lower() for entry in value}
                    filtered = [item for item in filtered if str(item.category).lower() in allowed]
                else:
                    filtered = [item for item in filtered if str(item.category).lower() == str(value).lower()]
            elif key == "id":
                filtered = [item for item in filtered if str(item.id) == str(value)]
        self.items = filtered
        return self

    def count(self):
        return len(self.items)

    def order_by(self, *args):
        self.items.sort(key=lambda item: (not bool(item.is_featured), -item.created_at.timestamp()))
        return self

    def offset(self, value):
        self._offset = value
        return self

    def limit(self, value):
        self._limit = value
        return self

    def all(self):
        items = self.items[self._offset:]
        if self._limit is not None:
            items = items[:self._limit]
        return items

    def first(self):
        items = self.all()
        return items[0] if items else None


class FakeMappingsResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class FakeExecuteResult:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return FakeMappingsResult(self._rows)


class FakeDB:
    def __init__(self, articles, scan_history_rows=None):
        self.articles = list(articles)
        self.scan_history_rows = scan_history_rows or []

    def query(self, model):
        return FakeQuery(self.articles)

    def execute(self, statement, params=None):
        return FakeExecuteResult(self.scan_history_rows)


def _article(*, title, category, featured=False, minutes=5):
    return SimpleNamespace(
        id=uuid.uuid4(),
        title=title,
        description=f"{title} description",
        content=f"<p>{title} content</p>",
        category=category,
        read_time=minutes,
        image_url=f"https://cdn.example.com/{title.lower().replace(' ', '-')}.png",
        is_featured=featured,
        created_at=datetime(2026, 5, 4, 10, 0, tzinfo=timezone.utc),
    )


def test_list_learning_articles_with_category_filter(client):
    phishing = _article(title="Spot Phishing", category="phishing_awareness", featured=True)
    password = _article(title="Password Hygiene", category="password_security")
    db = FakeDB([phishing, password])
    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db

    response = client.get("/learn/articles?category=phishing_awareness")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["data"]["total"] == 1
    assert payload["data"]["category"] == "phishing_awareness"
    assert payload["data"]["items"][0]["title"] == "Spot Phishing"


def test_get_learning_article_detail(client):
    article = _article(title="QR Scam Safety", category="qr_safety", featured=True)
    db = FakeDB([article])
    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db

    response = client.get(f"/learn/{article.id}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["data"]["id"] == str(article.id)
    assert payload["data"]["content"] == "<p>QR Scam Safety content</p>"


def test_learning_article_detail_not_found(client):
    db = FakeDB([])
    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db

    response = client.get(f"/learn/{uuid.uuid4()}")

    assert response.status_code == 404
    payload = response.json()
    assert payload["status"] == "error"
    assert payload["error_code"] == "ARTICLE_NOT_FOUND"


def test_recommended_articles_use_scan_history_categories(client):
    deepfake = _article(title="Spot Deepfakes", category="deepfake_awareness", featured=True)
    phishing = _article(title="Email Scam Guide", category="phishing_awareness")
    fallback = _article(title="General Safety", category="general_safety")
    scan_history_rows = [
        {"scan_type": "reality_video", "total": 4},
        {"scan_type": "email", "total": 2},
    ]
    db = FakeDB([deepfake, phishing, fallback], scan_history_rows=scan_history_rows)
    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db

    response = client.get("/learn/recommended")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "success"
    assert payload["data"]["meta"]["source"] == "history_match"
    assert payload["data"]["meta"]["matched_categories"] == ["deepfake_awareness", "misinformation", "email_security", "phishing_awareness"]
    assert [item["title"] for item in payload["data"]["items"]] == ["Spot Deepfakes", "Email Scam Guide"]
