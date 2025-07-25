from models import Session, Message

# session_metadata_storage will hold the metadata for each session
session_metadata_storage: list[Session] = []

# chat_storage will hold the messages for each session
chat_storage: dict[int, list[Message]] = {}
