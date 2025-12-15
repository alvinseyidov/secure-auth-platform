"""
Custom exceptions for authentication and token handling.
"""


class TokenError(Exception):
    """Base exception for all token-related errors."""
    pass


class TokenExpiredError(TokenError):
    """Raised when a token has expired."""
    pass


class TokenInvalidError(TokenError):
    """Raised when a token is malformed or signature verification fails."""
    pass


class TokenTypeMismatchError(TokenError):
    """
    Raised when using wrong token type (e.g., refresh token as access token).
    Prevents token confusion attacks.
    """
    pass

