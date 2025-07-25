from datetime import datetime, timezone

from fastapi import FastAPI
from starlette import status

from dto import SessionRequest
from models import Session
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
