import pytest
from fastapi.testclient import TestClient
from main import app
from storage import session_metadata_storage, chat_storage

client = TestClient(app)


@pytest.fixture
def create_session():
    """Fixture to create a session and return session data"""

    def _create_session(username="testuser"):
        response = client.post("/session", json={"session_user": username})
        assert response.status_code == 201
        return response.json()

    return _create_session


@pytest.fixture
def session_with_id(create_session):
    """Fixture that creates a session and returns just the session_id"""
    session_data = create_session()
    return session_data["session_id"]


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


def test_append_message_to_session_valid(create_session):
    # First create a session to append messages to
    session_data = create_session("testUser")
    session_id = session_data["session_id"]

    # Test appending a valid user message
    message_data = {"role": "user", "content": "Hello, this is a test message"}
    response = client.post(f"/session/{session_id}/messages", json=message_data)
    assert response.status_code == 201

    # Verify message was stored
    stored_messages = chat_storage[session_id]
    assert len(stored_messages) == 1
    assert stored_messages[0].role == "user"
    assert stored_messages[0].content == "Hello, this is a test message"


def test_append_message_to_session_valid_assistant(create_session):
    # First create a session
    session_data = create_session("testUser2")
    session_id = session_data["session_id"]

    # Test appending a valid assistant message
    message_data = {"role": "assistant", "content": "This is an assistant response"}
    response = client.post(f"/session/{session_id}/messages", json=message_data)
    assert response.status_code == 201

    # Verify message was stored
    stored_messages = chat_storage[session_id]
    assert len(stored_messages) == 1
    assert stored_messages[0].role == "assistant"
    assert stored_messages[0].content == "This is an assistant response"


def test_append_message_to_session_not_found():
    # Test appending to a non-existent session
    message_data = {"role": "user", "content": "This should fail"}
    response = client.post("/session/9999/messages", json=message_data)
    assert response.status_code == 404
    assert response.json()["detail"] == "Session not found"


@pytest.mark.parametrize("invalid_role", [
    "admin",
    "moderator",
    "guest",
    "USER",  # case sensitive
    "ASSISTANT",  # case sensitive
])
def test_append_message_to_session_invalid_role(create_session, invalid_role):
    # First create a session
    session_data = create_session("testUser4")
    session_id = session_data["session_id"]

    # Test appending message with invalid role
    message_data = {"role": invalid_role, "content": "This should fail"}
    response = client.post(f"/session/{session_id}/messages", json=message_data)
    assert response.status_code == 400  # Bad Request
    assert response.json()["detail"] == "Invalid role"


def test_append_message_to_session_invalid_content(create_session):
    # First create a session
    session_data = create_session("testUser5")
    session_id = session_data["session_id"]

    # Test with empty content (should fail validation)
    message_data = {"role": "user", "content": ""}
    response = client.post(f"/session/{session_id}/messages", json=message_data)
    assert response.status_code == 422  # Unprocessable Entity due to validation


def test_append_message_to_session_missing_fields(create_session):
    # First create a session
    session_data = create_session("testUser6")
    session_id = session_data["session_id"]

    # Test with missing role
    response = client.post(f"/session/{session_id}/messages", json={"content": "Hello"})
    assert response.status_code == 422

    # Test with missing content
    response = client.post(f"/session/{session_id}/messages", json={"role": "user"})
    assert response.status_code == 422


def test_get_messages_empty_session(create_session):
    """Test getting messages from an empty session"""
    session_data = create_session("testUser")
    session_id = session_data["session_id"]

    response = client.get(f"/session/{session_id}/messages")
    assert response.status_code == 200
    assert response.json() == []


def test_get_messages_all_default(create_session):
    """Test getting all messages (default behavior)"""
    session_data = create_session("testUser")
    session_id = session_data["session_id"]

    # Add some messages
    client.post(f"/session/{session_id}/messages", json={"role": "user", "content": "Hello"})
    client.post(f"/session/{session_id}/messages", json={"role": "assistant", "content": "Hi there"})
    client.post(f"/session/{session_id}/messages", json={"role": "user", "content": "How are you?"})

    response = client.get(f"/session/{session_id}/messages")
    assert response.status_code == 200
    messages = response.json()
    assert len(messages) == 3
    assert messages[0]["role"] == "user"
    assert messages[0]["content"] == "Hello"
    assert messages[1]["role"] == "assistant"
    assert messages[1]["content"] == "Hi there"
    assert messages[2]["role"] == "user"
    assert messages[2]["content"] == "How are you?"


def test_get_messages_all_explicit(create_session):
    """Test getting all messages with explicit 'all' parameter"""
    session_data = create_session("testUser")
    session_id = session_data["session_id"]

    # Add some messages
    client.post(f"/session/{session_id}/messages", json={"role": "user", "content": "Hello"})
    client.post(f"/session/{session_id}/messages", json={"role": "assistant", "content": "Hi there"})
    client.post(f"/session/{session_id}/messages", json={"role": "user", "content": "How are you?"})

    response = client.get(f"/session/{session_id}/messages?role=all")
    assert response.status_code == 200
    messages = response.json()
    assert len(messages) == 3


def test_get_messages_filter_user_only(create_session):
    """Test getting only user messages"""
    session_data = create_session("testUser")
    session_id = session_data["session_id"]

    # Add some messages
    client.post(f"/session/{session_id}/messages", json={"role": "user", "content": "Hello"})
    client.post(f"/session/{session_id}/messages", json={"role": "assistant", "content": "Hi there"})
    client.post(f"/session/{session_id}/messages", json={"role": "user", "content": "How are you?"})

    response = client.get(f"/session/{session_id}/messages?role=user")
    assert response.status_code == 200
    messages = response.json()
    assert len(messages) == 2
    assert all(msg["role"] == "user" for msg in messages)
    assert messages[0]["content"] == "Hello"
    assert messages[1]["content"] == "How are you?"


def test_get_messages_filter_assistant_only(create_session):
    """Test getting only assistant messages"""
    session_data = create_session("testUser")
    session_id = session_data["session_id"]

    # Add some messages
    client.post(f"/session/{session_id}/messages", json={"role": "user", "content": "Hello"})
    client.post(f"/session/{session_id}/messages", json={"role": "assistant", "content": "Hi there"})
    client.post(f"/session/{session_id}/messages", json={"role": "user", "content": "How are you?"})

    response = client.get(f"/session/{session_id}/messages?role=assistant")
    assert response.status_code == 200
    messages = response.json()
    assert len(messages) == 1
    assert all(msg["role"] == "assistant" for msg in messages)
    assert messages[0]["content"] == "Hi there"


def test_get_messages_session_not_found():
    """Test getting messages from a non-existent session"""
    response = client.get("/session/9999/messages")
    assert response.status_code == 404
    assert response.json()["detail"] == "Session not found"


@pytest.mark.parametrize("invalid_role", [
    "admin",
    "moderator",
    "guest",
    "USER",  # case sensitive
    "ASSISTANT",  # case sensitive
    "invalid",
    "123"
])
def test_get_messages_invalid_role_parameter(create_session, invalid_role):
    """Test getting messages with invalid role parameter"""
    session_data = create_session("testUser")
    session_id = session_data["session_id"]

    response = client.get(f"/session/{session_id}/messages?role={invalid_role}")
    assert response.status_code == 422  # Unprocessable Entity due to regex validation
