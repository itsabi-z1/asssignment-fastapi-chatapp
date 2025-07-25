class Session:
    def __init__(self, session_id, session_user, created_at):
        self.session_id: int = session_id
        self.session_user: str = session_user
        self.created_at: str = created_at


class Message:
    def __init__(self, role, content):
        self.role: str = role
        self.content: str = content
