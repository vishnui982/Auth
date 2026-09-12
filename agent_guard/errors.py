class GuardError(Exception):
    """An expected, safe-to-disclose rejection."""

    def __init__(self, code: str, status: int = 403):
        super().__init__(code)
        self.code = code
        self.status = status
