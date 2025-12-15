"""
JWT token creation and validation.

Uses HS256 symmetric signing with Django's SECRET_KEY.
For production with multiple services, consider RS256 with key pairs.
"""
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from django.conf import settings

from .exceptions import TokenExpiredError, TokenInvalidError, TokenTypeMismatchError


def _get_token_settings():
    """Token lifetimes from settings with secure defaults."""
    return {
        'access_lifetime': getattr(settings, 'JWT_ACCESS_TOKEN_LIFETIME', 600),  # 10 min
        'refresh_lifetime': getattr(settings, 'JWT_REFRESH_TOKEN_LIFETIME', 604800),  # 7 days
        'algorithm': 'HS256',
    }


def _get_signing_key() -> str:
    """
    Get the key used for signing tokens.
    Using Django's SECRET_KEY keeps key management simple.
    """
    return settings.SECRET_KEY


def hash_refresh_token(raw_token: str) -> str:
    """
    Hash a refresh token for database storage.
    
    SHA-256 is sufficient here because:
    - Refresh tokens are already high-entropy (JWT with random jti)
    - We're protecting against DB leak, not brute-force
    - No salt needed since input is cryptographically random
    """
    return hashlib.sha256(raw_token.encode()).hexdigest()


def create_access_token(user) -> str:
    """
    Create a short-lived access token for API authentication.
    
    Short lifetime limits damage window if token is stolen.
    Client must use refresh token to get new access tokens.
    """
    config = _get_token_settings()
    now = datetime.now(timezone.utc)

    payload = {
        'user_id': user.id,
        'email': user.email,
        'token_type': 'access',
        'iat': now,
        'exp': now + timedelta(seconds=config['access_lifetime']),
    }

    return jwt.encode(payload, _get_signing_key(), algorithm=config['algorithm'])


def create_refresh_token(user, jti: str = None) -> tuple[str, str, datetime, datetime]:
    """
    Create a long-lived refresh token for obtaining new access tokens.
    
    Returns:
        Tuple of (raw_token, jti, issued_at, expires_at)
        Caller must store the hash in DB.
    """
    config = _get_token_settings()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=config['refresh_lifetime'])

    # Generate unique token ID for DB tracking
    if jti is None:
        jti = str(uuid.uuid4())

    payload = {
        'user_id': user.id,
        'token_type': 'refresh',
        'jti': jti,
        'iat': now,
        'exp': expires,
    }

    raw_token = jwt.encode(payload, _get_signing_key(), algorithm=config['algorithm'])
    return raw_token, jti, now, expires


def decode_token(token: str, expected_type: str = None) -> dict[str, Any]:
    """
    Decode and validate a JWT token.
    
    Args:
        token: The JWT string
        expected_type: If provided, validates token_type matches ('access' or 'refresh')
    
    Returns:
        Decoded payload dict
    
    Raises:
        TokenExpiredError: Token has expired
        TokenInvalidError: Token is malformed or signature invalid
        TokenTypeMismatchError: Token type doesn't match expected_type
    """
    config = _get_token_settings()

    try:
        payload = jwt.decode(
            token,
            _get_signing_key(),
            algorithms=[config['algorithm']],
        )
    except jwt.ExpiredSignatureError:
        raise TokenExpiredError('Token has expired')
    except jwt.InvalidTokenError as e:
        raise TokenInvalidError(f'Invalid token: {e}')

    # Validate token type if specified
    if expected_type:
        token_type = payload.get('token_type')
        if token_type != expected_type:
            raise TokenTypeMismatchError(
                f'Expected {expected_type} token, got {token_type}'
            )

    return payload


def decode_token_unverified(token: str) -> dict[str, Any]:
    """
    Decode token WITHOUT signature verification.
    
    Used only to extract user_id from potentially tampered tokens
    during token reuse detection. Never trust data from this for auth.
    """
    try:
        return jwt.decode(token, options={'verify_signature': False})
    except jwt.InvalidTokenError:
        return {}


def create_token_pair(user) -> dict[str, str]:
    """
    Create both access and refresh tokens for a user.
    Convenience function for login responses.
    
    Note: This doesn't persist the refresh token. Use token_services
    for DB-backed token creation.
    """
    raw_refresh, _, _, _ = create_refresh_token(user)
    return {
        'access_token': create_access_token(user),
        'refresh_token': raw_refresh,
    }
