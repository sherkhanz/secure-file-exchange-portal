"""
Unit Tests: Secure File Exchange Portal
Tests individual endpoints and logic in isolation using FastAPI TestClient.
"""
import os
import sys
import tempfile
import pytest
from fastapi.testclient import TestClient

_tmp_db    = tempfile.mkdtemp()
_tmp_files = tempfile.mkdtemp()
os.environ["DB_PATH"]      = os.path.join(_tmp_db, "test_portal.db")
os.environ["STORAGE_PATH"] = _tmp_files
os.environ["API_TOKEN"]    = "test-token-unit"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from main import app  # noqa: E402

client  = TestClient(app)
HEADERS = {"x-api-token": "test-token-unit"}


def test_health_returns_ok():
    """GET /health must return 200 and status=ok."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_upload_without_token_returns_401():
    """POST /upload without x-api-token must return 401."""
    response = client.post(
        "/upload",
        files={"file": ("test.txt", b"data", "text/plain")},
    )
    assert response.status_code == 401


def test_upload_with_wrong_token_returns_401():
    """POST /upload with incorrect token must return 401."""
    response = client.post(
        "/upload",
        headers={"x-api-token": "wrong-token"},
        files={"file": ("test.txt", b"data", "text/plain")},
    )
    assert response.status_code == 401


def test_upload_returns_file_id():
    """POST /upload with valid token must return file_id and sha256."""
    response = client.post(
        "/upload",
        headers=HEADERS,
        files={"file": ("unit_test.txt", b"unit test content", "text/plain")},
    )
    assert response.status_code == 200
    data = response.json()
    assert "file_id" in data
    assert "sha256" in data
    assert len(data["file_id"]) == 36


def test_create_link_returns_token():
    """POST /links must return a token for a valid file_id."""
    upload = client.post(
        "/upload",
        headers=HEADERS,
        files={"file": ("link_test.txt", b"link test content", "text/plain")},
    )
    file_id = upload.json()["file_id"]
    response = client.post(
        "/links",
        headers={**HEADERS, "Content-Type": "application/json"},
        json={"file_id": file_id, "expires_in_minutes": 60},
    )
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    assert "expires_at" in data
    assert "download_url" in data


def test_create_link_invalid_file_id_returns_404():
    """POST /links with unknown file_id must return 404."""
    response = client.post(
        "/links",
        headers={**HEADERS, "Content-Type": "application/json"},
        json={"file_id": "00000000-0000-0000-0000-000000000000", "expires_in_minutes": 60},
    )
    assert response.status_code == 404


def test_download_with_valid_token_returns_200():
    """GET /download/{token} with a valid token must return 200."""
    upload = client.post(
        "/upload",
        headers=HEADERS,
        files={"file": ("download_test.txt", b"download content", "text/plain")},
    )
    file_id = upload.json()["file_id"]
    link = client.post(
        "/links",
        headers={**HEADERS, "Content-Type": "application/json"},
        json={"file_id": file_id, "expires_in_minutes": 60},
    )
    token = link.json()["token"]
    response = client.get(f"/download/{token}", headers=HEADERS)
    assert response.status_code == 200


def test_download_with_invalid_token_returns_404():
    """GET /download/{token} with unknown token must return 404."""
    response = client.get(
        "/download/00000000-0000-0000-0000-000000000000",
        headers=HEADERS,
    )
    assert response.status_code == 404


def test_revoke_token_blocks_download():
    """POST /revoke/{token} must cause subsequent download to return 410."""
    upload = client.post(
        "/upload",
        headers=HEADERS,
        files={"file": ("revoke_test.txt", b"revoke content", "text/plain")},
    )
    file_id = upload.json()["file_id"]
    link = client.post(
        "/links",
        headers={**HEADERS, "Content-Type": "application/json"},
        json={"file_id": file_id, "expires_in_minutes": 60},
    )
    token = link.json()["token"]
    revoke = client.post(f"/revoke/{token}", headers=HEADERS)
    assert revoke.status_code == 200
    download = client.get(f"/download/{token}", headers=HEADERS)
    assert download.status_code == 410


def test_revoke_invalid_token_returns_404():
    """POST /revoke/{token} with unknown token must return 404."""
    response = client.post(
        "/revoke/00000000-0000-0000-0000-000000000000",
        headers=HEADERS,
    )
    assert response.status_code == 404