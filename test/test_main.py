import pytest
from fastapi.testclient import TestClient
from main import app
from storage import session_metadata_storage, chat_storage

client = TestClient(app)


def test_session_create():
    # Test creating a session with valid input
    response = client.post("/session", json={"session_user": "testUser"})
    assert response.status_code == 201  # Created
    data = response.json()
    assert "session_id" in data
    assert data["session_user"] == "testuser"  # Should be lowercased
    assert data["session_id"] == 1  # Assuming this is the first session created
    assert data["created_at"] is not None


# Test creating a session with invalid username
@pytest.mark.parametrize("test_input,expected",
                         [
                             ("", 422),  # Empty username should return 422 Unprocessable Entity
                             ("   ", 422),  # Whitespace username should also return 422
                             (None, 422)  # None username should return 422
                         ])
def test_session_create_no_username(test_input, expected):
    response = client.post("/session", json={"session_user": test_input})
    assert response.status_code == expected  # Unprocessable Entity


def test_session_create_and_stored():
    # Test creating a session with valid input
    response = client.post("/session", json={"session_user": "test_user"})
    assert response.status_code == 201  # Created

    session_id = response.json()["session_id"]
    stored_session = list(filter(lambda x: x.session_id == session_id, session_metadata_storage))
    assert len(stored_session) == 1  # Should be exactly one session with this ID
    assert stored_session[0].session_user == "test_user"

    assert chat_storage.get(session_id) is not None  # Should have an empty list for this session ID
