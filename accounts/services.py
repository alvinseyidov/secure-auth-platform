from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from django.conf import settings
from django.contrib.auth import authenticate
from django.db import transaction
from django.utils import timezone

from .exceptions import TokenError, TokenExpiredError, TokenInvalidError
from .jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
    decode_token_unverified,
    hash_refresh_token,
)
from .models import AuthenticationEvent, LoginAttempt, RefreshToken, User


@dataclass
class AuthResult:
    """Result of authentication attempt."""
    success: bool
    user: Optional[User] = None
    error: str = ''
    locked: bool = False


def get_client_ip(request) -> str:
    """
    Extract client IP, respecting X-Forwarded-For from trusted proxies.
    First IP in chain is the original client.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def get_brute_force_settings():
    """Get brute-force protection settings with defaults."""
    return {
        'max_attempts': getattr(settings, 'AUTH_MAX_ATTEMPTS', 5),
        'lockout_duration': getattr(settings, 'AUTH_LOCKOUT_DURATION', 900),  # 15 min
        'attempt_window': getattr(settings, 'AUTH_ATTEMPT_WINDOW', 900),  # 15 min
    }


def _get_recent_attempts(identifier: str, identifier_type: str, window_seconds: int) -> int:
    """Count failed attempts within the time window."""
    window_start = timezone.now() - timedelta(seconds=window_seconds)
    return LoginAttempt.objects.filter(
        identifier=identifier,
        identifier_type=identifier_type,
        attempt_time__gte=window_start,
    ).count()


def _record_failed_attempt(identifier: str, identifier_type: str):
    """Record a failed login attempt."""
    LoginAttempt.objects.create(
        identifier=identifier,
        identifier_type=identifier_type,
    )


def _clear_attempts(identifier: str, identifier_type: str):
    """Clear failed attempts after successful login."""
    LoginAttempt.objects.filter(
        identifier=identifier,
        identifier_type=identifier_type,
    ).delete()


def _make_email_ip_key(email: str, ip_address: str) -> str:
    """
    Composite key for per-IP email tracking.
    Prevents attackers from locking out legitimate users via DoS.
    """
    return f'{email.lower()}:{ip_address}'


def _is_locked(email: str, ip_address: str) -> bool:
    """
    Check if (email, IP) pair or IP alone is locked out.
    Email lockout is per-IP to prevent DoS attacks on legitimate users.
    """
    config = get_brute_force_settings()
    max_attempts = config['max_attempts']
    window = config['attempt_window']

    # Email attempts tracked per-IP (attacker can't lock out other IPs)
    email_ip_key = _make_email_ip_key(email, ip_address)
    email_attempts = _get_recent_attempts(email_ip_key, 'email_ip', window)

    # IP attempts tracked globally (catches credential stuffing)
    ip_attempts = _get_recent_attempts(ip_address, 'ip', window)

    return email_attempts >= max_attempts or ip_attempts >= max_attempts


def log_auth_event(
    event_type: str,
    email: str,
    ip_address: str,
    user: Optional[User] = None,
    user_agent: str = '',
):
    """Create an authentication audit log entry."""
    AuthenticationEvent.objects.create(
        user=user,
        email_attempted=email.lower(),
        ip_address=ip_address,
        event_type=event_type,
        user_agent=user_agent[:500] if user_agent else '',  # Truncate long UAs
    )


def authenticate_user(request, email: str, password: str) -> AuthResult:
    """
    Authenticate user with brute-force protection.
    
    Returns generic error message regardless of failure reason
    to prevent user enumeration attacks.
    """
    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    email_lower = email.lower()

    # Check lockout before attempting authentication
    if _is_locked(email_lower, ip_address):
        log_auth_event(
            AuthenticationEvent.EventType.ACCOUNT_LOCKED,
            email_lower,
            ip_address,
            user_agent=user_agent,
        )
        return AuthResult(
            success=False,
            error='Account temporarily locked. Try again later.',
            locked=True,
        )

    # Use Django's auth system
    user = authenticate(request, username=email_lower, password=password)

    if user is None:
        # Record failed attempt for email+IP pair and IP globally
        email_ip_key = _make_email_ip_key(email_lower, ip_address)
        _record_failed_attempt(email_ip_key, 'email_ip')
        _record_failed_attempt(ip_address, 'ip')

        # Check if this attempt triggered lockout
        if _is_locked(email_lower, ip_address):
            log_auth_event(
                AuthenticationEvent.EventType.ACCOUNT_LOCKED,
                email_lower,
                ip_address,
                user_agent=user_agent,
            )
        else:
            log_auth_event(
                AuthenticationEvent.EventType.LOGIN_FAILED,
                email_lower,
                ip_address,
                user_agent=user_agent,
            )

        # Generic message prevents user enumeration
        return AuthResult(success=False, error='Invalid credentials.')

    if not user.is_active:
        # Treat inactive as invalid to prevent enumeration
        email_ip_key = _make_email_ip_key(email_lower, ip_address)
        _record_failed_attempt(email_ip_key, 'email_ip')
        log_auth_event(
            AuthenticationEvent.EventType.LOGIN_FAILED,
            email_lower,
            ip_address,
            user_agent=user_agent,
        )
        return AuthResult(success=False, error='Invalid credentials.')

    # Success: clear failed attempts for this email+IP pair
    email_ip_key = _make_email_ip_key(email_lower, ip_address)
    _clear_attempts(email_ip_key, 'email_ip')

    log_auth_event(
        AuthenticationEvent.EventType.LOGIN_SUCCESS,
        email_lower,
        ip_address,
        user=user,
        user_agent=user_agent,
    )

    return AuthResult(success=True, user=user)


def cleanup_old_attempts(days: int = 7):
    """
    Remove old LoginAttempt records.
    Run periodically via management command or celery.
    """
    cutoff = timezone.now() - timedelta(days=days)
    deleted, _ = LoginAttempt.objects.filter(attempt_time__lt=cutoff).delete()
    return deleted


# =============================================================================
# TOKEN SERVICES
# =============================================================================

@dataclass
class TokenResult:
    """Result of token operations."""
    success: bool
    access_token: str = ''
    refresh_token: str = ''
    error: str = ''


def create_token_pair_for_user(
    user: User,
    ip_address: str = None,
    user_agent: str = '',
) -> TokenResult:
    """
    Create access + refresh tokens and persist refresh token to DB.
    """
    raw_refresh, jti, issued_at, expires_at = create_refresh_token(user)
    token_hash = hash_refresh_token(raw_refresh)

    RefreshToken.objects.create(
        user=user,
        token_hash=token_hash,
        jti=jti,
        issued_at=issued_at,
        expires_at=expires_at,
        created_ip=ip_address,
        user_agent=user_agent[:500] if user_agent else '',
    )

    return TokenResult(
        success=True,
        access_token=create_access_token(user),
        refresh_token=raw_refresh,
    )


def _revoke_all_user_tokens(user: User):
    """Revoke all active refresh tokens for a user."""
    RefreshToken.objects.filter(
        user=user,
        revoked_at__isnull=True,
    ).update(revoked_at=timezone.now())


def rotate_refresh_token(
    raw_refresh_token: str,
    ip_address: str = None,
    user_agent: str = '',
) -> TokenResult:
    """
    Rotate a refresh token: invalidate old, issue new pair.
    
    Detects token reuse attacks: if a revoked token is used, all tokens
    for that user are revoked as a security measure.
    """
    # Decode and validate the token
    try:
        payload = decode_token(raw_refresh_token, expected_type='refresh')
    except TokenExpiredError:
        return TokenResult(success=False, error='Refresh token has expired')
    except TokenError as e:
        return TokenResult(success=False, error=str(e))

    user_id = payload.get('user_id')
    jti = payload.get('jti')

    if not user_id or not jti:
        return TokenResult(success=False, error='Invalid token payload')

    # Find user
    try:
        user = User.objects.get(id=user_id, is_active=True)
    except User.DoesNotExist:
        return TokenResult(success=False, error='User not found or inactive')

    token_hash = hash_refresh_token(raw_refresh_token)

    with transaction.atomic():
        # Look up the stored token
        try:
            stored_token = RefreshToken.objects.select_for_update().get(
                token_hash=token_hash,
                jti=jti,
            )
        except RefreshToken.DoesNotExist:
            # Token not in DB or tampered - suspicious
            _handle_token_reuse(user, ip_address, user_agent)
            return TokenResult(success=False, error='Invalid refresh token')

        # Check if already revoked - this is a token reuse attack
        if stored_token.is_revoked:
            _handle_token_reuse(user, ip_address, user_agent)
            return TokenResult(success=False, error='Token has been revoked')

        # Check expiration (belt and suspenders - JWT decode already checks)
        if stored_token.is_expired:
            return TokenResult(success=False, error='Refresh token has expired')

        # Create new token pair
        raw_new_refresh, new_jti, issued_at, expires_at = create_refresh_token(user)
        new_token_hash = hash_refresh_token(raw_new_refresh)

        new_stored_token = RefreshToken.objects.create(
            user=user,
            token_hash=new_token_hash,
            jti=new_jti,
            issued_at=issued_at,
            expires_at=expires_at,
            created_ip=ip_address,
            user_agent=user_agent[:500] if user_agent else '',
        )

        # Revoke old token and link to new one
        stored_token.revoked_at = timezone.now()
        stored_token.replaced_by = new_stored_token
        stored_token.save(update_fields=['revoked_at', 'replaced_by'])

    return TokenResult(
        success=True,
        access_token=create_access_token(user),
        refresh_token=raw_new_refresh,
    )


def _handle_token_reuse(user: User, ip_address: str, user_agent: str):
    """
    Handle detected token reuse attack.
    Revokes all user tokens and logs security event.
    """
    _revoke_all_user_tokens(user)

    log_auth_event(
        AuthenticationEvent.EventType.TOKEN_REUSE_DETECTED,
        user.email,
        ip_address or '0.0.0.0',
        user=user,
        user_agent=user_agent,
    )


def revoke_refresh_token(raw_refresh_token: str) -> bool:
    """
    Revoke a specific refresh token (logout).
    
    Returns True if token was found and revoked, False otherwise.
    """
    try:
        payload = decode_token(raw_refresh_token, expected_type='refresh')
    except TokenError:
        # Invalid token, nothing to revoke
        return False

    token_hash = hash_refresh_token(raw_refresh_token)
    jti = payload.get('jti')

    if not jti:
        return False

    updated = RefreshToken.objects.filter(
        token_hash=token_hash,
        jti=jti,
        revoked_at__isnull=True,
    ).update(revoked_at=timezone.now())

    return updated > 0


def revoke_all_user_tokens(user: User) -> int:
    """
    Revoke all refresh tokens for a user (password change, security event).
    Returns count of revoked tokens.
    """
    return RefreshToken.objects.filter(
        user=user,
        revoked_at__isnull=True,
    ).update(revoked_at=timezone.now())

