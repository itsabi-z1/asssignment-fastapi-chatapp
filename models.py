class Session:
    def __init__(self, session_id, session_user, created_at):
        self.session_id = session_id
        self.session_user = session_user
        self.created_at = created_at


class Message:
    def __init__(self, role, content):
        self.role = role
        self.content = content
