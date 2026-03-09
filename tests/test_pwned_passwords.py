import types

from app.services import pwned_passwords as pp


class DummyResp:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception("error")


def test_password_pwned_lookup(monkeypatch):
    # SHA1 of "password" is 5BAA6...E0
    prefix = "5BAA6"
    suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
    body = f"{suffix}:{3}\nOTHER:1"

    def fake_get(url, headers=None, timeout=5):
        assert url.endswith(prefix)
        return DummyResp(body)

    monkeypatch.setattr(pp.requests, "get", fake_get)
    monkeypatch.setattr(pp, "_cache_get", lambda prefix: None)
    monkeypatch.setattr(pp, "_cache_set", lambda prefix, value: None)

    count = pp.check_password_pwned("password")
    assert count == 3
