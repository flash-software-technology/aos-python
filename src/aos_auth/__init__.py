"""AOS identity engine SDK for Python backends."""
from .client import ROOT, VERSION, Aos, AsyncAos
from .errors import AosError, BadSignatureError, InvalidTokenError
from .token import Claims, token_from_header
from .webhook import sign_webhook, verify_webhook

__all__ = [
    "Aos", "AsyncAos", "AosError", "BadSignatureError", "Claims", "InvalidTokenError",
    "ROOT", "VERSION", "sign_webhook", "token_from_header", "verify_webhook",
]
__version__ = VERSION
