import pytest


def _register_and_login(client, email: str, password: str = "StrongPass123!", name: str = "Analyst"):
    reg = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password, "display_name": name},
    )
    assert reg.status_code == 201, reg.text
    return reg.json()


def test_health_and_model_status_endpoints(client):
    health = client.get("/api/v1/health")
    assert health.status_code == 200
    body = health.json()
    assert body["status"] == "ok"
    assert body["auth_mode"] == "local_jwt"

    model_status = client.get("/api/v1/model/status")
    assert model_status.status_code == 200
    assert "model_loaded" in model_status.json()
    assert len(model_status.json()["feature_names"]) >= 15


@pytest.mark.parametrize(
    "test_url",
    [
        "https://example.com",
        "http://192.168.1.1/login/verify",
        "https://example.com@evil.example",
        "https://example.com/login/verify",
    ],
)
def test_scan_example_urls_end_to_end(client, test_url: str):
    res = client.post("/api/v1/scan", json={"url": test_url})
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["submitted_url"] == test_url
    assert 0 <= data["risk_score"] <= 100
    assert data["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert data["persisted"] is False
    assert len(data["extracted_features"]) >= 15
    assert len(data["threat_intelligence"]) == 4
    assert "does not guarantee" in data["safety_disclaimer"]


def test_scan_rejects_ssrf_and_invalid_urls(client):
    ssrf_resp = client.post("/api/v1/scan", json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert ssrf_resp.status_code == 400

    bad_scheme = client.post("/api/v1/scan", json={"url": "javascript:alert(1)"})
    assert bad_scheme.status_code == 422


def test_protected_routes_require_authentication(client):
    assert client.get("/api/v1/scans").status_code == 401
    assert client.get("/api/v1/dashboard/stats").status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 401


def test_user_registration_login_password_reset_and_profile(client):
    auth = _register_and_login(client, "alice@example.org", "InitialPass123!", "Alice")
    headers = {"Authorization": f"Bearer {auth['access_token']}"}

    me = client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["email"] == "alice@example.org"

    upd = client.patch("/api/v1/auth/me", json={"display_name": "Alice Security"}, headers=headers)
    assert upd.status_code == 200
    assert upd.json()["display_name"] == "Alice Security"

    # Reset password and log in with new password
    reset = client.post(
        "/api/v1/auth/reset-password",
        json={"email": "alice@example.org", "new_password": "NewStrongPass456!"},
    )
    assert reset.status_code == 200

    bad_login = client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.org", "password": "InitialPass123!"},
    )
    assert bad_login.status_code == 401

    good_login = client.post(
        "/api/v1/auth/login",
        json={"email": "alice@example.org", "password": "NewStrongPass456!"},
    )
    assert good_login.status_code == 200
    assert "access_token" in good_login.json()


def test_user_data_isolation_and_history_crud(client):
    alice = _register_and_login(client, "alice2@example.org")
    bob = _register_and_login(client, "bob2@example.org")
    alice_headers = {"Authorization": f"Bearer {alice['access_token']}"}
    bob_headers = {"Authorization": f"Bearer {bob['access_token']}"}

    scan1 = client.post("/api/v1/scan", json={"url": "https://example.com"}, headers=alice_headers)
    scan2 = client.post("/api/v1/scan", json={"url": "http://192.168.1.1/login/verify"}, headers=alice_headers)
    assert scan1.status_code == 200 and scan2.status_code == 200
    scan1_id = scan1.json()["id"]
    assert scan1.json()["persisted"] is True

    # Bob cannot see, read, or delete Alice's scans
    bob_list = client.get("/api/v1/scans", headers=bob_headers)
    assert bob_list.status_code == 200
    assert bob_list.json()["total"] == 0

    bob_get = client.get(f"/api/v1/scans/{scan1_id}", headers=bob_headers)
    assert bob_get.status_code == 404

    bob_del = client.delete(f"/api/v1/scans/{scan1_id}", headers=bob_headers)
    assert bob_del.status_code == 404

    # Alice can view dashboard stats, filter scans, view detail, and delete her own scan
    stats = client.get("/api/v1/dashboard/stats", headers=alice_headers)
    assert stats.status_code == 200
    assert stats.json()["total_scans"] == 2

    filtered = client.get("/api/v1/scans", params={"domain": "192.168.1.1"}, headers=alice_headers)
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1

    detail = client.get(f"/api/v1/scans/{scan1_id}", headers=alice_headers)
    assert detail.status_code == 200
    assert detail.json()["submitted_url"] == "https://example.com"

    deleted = client.delete(f"/api/v1/scans/{scan1_id}", headers=alice_headers)
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True

    after_list = client.get("/api/v1/scans", headers=alice_headers)
    assert after_list.json()["total"] == 1

