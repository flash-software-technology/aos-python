class AosError(Exception):
    """An error answer from the engine. A permission deny is not an error."""

    def __init__(self, status: int, code: str, message: str, details: dict | None = None):
        super().__init__(f"{message} [{code}]")
        self.status = status
        self.code = code
        self.message = message
        self.details = details or {}


class InvalidTokenError(Exception):
    """A token that is malformed, signed by another tenant, tampered with or expired."""

    def __init__(self) -> None:
        super().__init__("aos: invalid or expired token")


class BadSignatureError(Exception):
    """A webhook delivery not signed with the endpoint's secret, or too old."""

    def __init__(self) -> None:
        super().__init__("aos: webhook signature does not match")
