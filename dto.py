from pydantic import BaseModel, Field


class SessionRequest(BaseModel):
    session_user: str = Field(min_length=1, pattern=r"^\S.*\S$|^\S$")
