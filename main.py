from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query
from starlette import status

from dto import SessionRequest, MessageRequest
from models import Session, Message
from storage import session_metadata_storage, chat_storage

app = FastAPI(title="Chat Application")


@app.post("/session", status_code=status.HTTP_201_CREATED)
async def create_session(session: SessionRequest):
    new_session = Session(
        len(session_metadata_storage) + 1,
        session.session_user.strip().lower(),
        str(datetime.now(tz=timezone.utc))
    )

    # Append the new session to the session metadata storage
    session_metadata_storage.append(new_session)

    # Initialize an empty list for the new session in chat storage
    chat_storage[new_session.session_id] = []

    return new_session


@app.post("/session/{session_id}/messages", status_code=status.HTTP_201_CREATED)
async def append_message_to_session(session_id: int, message: MessageRequest):
    # Validates if session exists
    if len(session_metadata_storage) < session_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    # Validates if role is user or assistant
    if message.role not in ["user", "assistant"]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role")

    # Appends message to chat_store[session_id]
    chat_storage[session_id].append(Message(**message.model_dump()))


@app.get("/session/{session_id}/messages", status_code=status.HTTP_200_OK)
async def get_messages(session_id: int, role: str = Query(default="all", pattern="^(user|assistant|all)$")):
    # Validates if session exists
    if len(session_metadata_storage) < session_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    messages = chat_storage[session_id]

    # Filter messages based on role if not "all"
    if role != "all":
        messages = [message for message in messages if message.role == role]

    return messages
