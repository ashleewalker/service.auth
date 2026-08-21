from fastapi.testclient import TestClient

from app.main import app, refresh_tokens, users, audit_events

client = TestClient(app)


def setup_function():
    users.clear()
    refresh_tokens.clear()
    audit_events.clear()


def test_register_login_and_me():
    registered = client.post(
        "/v1/auth/register",
        json={"email": "alice@example.com", "password": "correct horse battery staple"},
    )
    assert registered.status_code == 201
    token = registered.json()["access_token"]

    response = client.get("/v1/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["email"] == "alice@example.com"


def test_refresh_token_rotates():
    registered = client.post(
        "/v1/auth/register",
        json={"email": "bob@example.com", "password": "correct horse battery staple"},
    )
    refresh = registered.json()["refresh_token"]

    rotated = client.post("/v1/auth/refresh", json={"refresh_token": refresh})
    assert rotated.status_code == 200
    assert rotated.json()["refresh_token"] != refresh

    replay = client.post("/v1/auth/refresh", json={"refresh_token": refresh})
    assert replay.status_code == 401


def test_scope_protects_audit_endpoint():
    registered = client.post(
        "/v1/auth/register",
        json={"email": "carol@example.com", "password": "correct horse battery staple"},
    )
    token = registered.json()["access_token"]
    response = client.get("/v1/audit", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_privileged_scope_cannot_be_self_assigned():
    response = client.post(
        "/v1/auth/register",
        json={
            "email": "admin@example.com",
            "password": "correct horse battery staple",
            "scopes": ["audit:read"],
        },
    )
    assert response.status_code == 403
