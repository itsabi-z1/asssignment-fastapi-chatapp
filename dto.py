from pydantic import BaseModel, Field


class SessionRequest(BaseModel):
    session_user: str = Field(min_length=1, pattern=r"^\S.*\S$|^\S$")

class MessageRequest(BaseModel):
    role: str = Field(min_length=3, pattern=r"^\S.*\S$|^\S$")
    content: str = Field(min_length=1, pattern=r"^\S.*\S$|^\S$")
