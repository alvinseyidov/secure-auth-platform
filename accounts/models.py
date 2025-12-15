from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone

from .managers import UserManager


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model using email as primary identifier.
    AbstractBaseUser gives us full control over authentication fields.
    """

    email = models.EmailField(unique=True, db_index=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'

    def __str__(self):
        return self.email


class AuthenticationEvent(models.Model):
    """
    Immutable audit log for authentication events.
    Critical for security monitoring and incident response.
    """

    class EventType(models.TextChoices):
        LOGIN_SUCCESS = 'LOGIN_SUCCESS', 'Login Success'
        LOGIN_FAILED = 'LOGIN_FAILED', 'Login Failed'
        ACCOUNT_LOCKED = 'ACCOUNT_LOCKED', 'Account Locked'
        LOGOUT = 'LOGOUT', 'Logout'
        TOKEN_REUSE_DETECTED = 'TOKEN_REUSE', 'Token Reuse Detected'

    # Nullable: failed attempts won't have a user
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='auth_events',
    )
    email_attempted = models.EmailField(db_index=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    event_type = models.CharField(max_length=20, choices=EventType.choices, db_index=True)
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        verbose_name = 'authentication event'
        verbose_name_plural = 'authentication events'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['email_attempted', 'event_type', 'timestamp']),
            models.Index(fields=['ip_address', 'event_type', 'timestamp']),
        ]

    def __str__(self):
        return f'{self.event_type} - {self.email_attempted} ({self.ip_address})'


class LoginAttempt(models.Model):
    """
    Tracks failed login attempts for brute-force detection.
    Separate from AuthenticationEvent for efficient querying and cleanup.
    """

    identifier = models.CharField(max_length=255, db_index=True)
    identifier_type = models.CharField(max_length=10)
    attempt_time = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [
            models.Index(fields=['identifier', 'identifier_type', 'attempt_time']),
        ]


class RefreshToken(models.Model):
    """
    Database-backed refresh tokens for rotation and revocation.
    
    Stores hash of token, not the raw value. SHA-256 is sufficient here
    because refresh tokens are already high-entropy (cryptographically random).
    We're not protecting against brute-force; we're preventing DB leak exposure.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='refresh_tokens',
    )
    # SHA-256 hash of the raw JWT
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    # JWT ID claim for token identification
    jti = models.CharField(max_length=36, unique=True, db_index=True)
    issued_at = models.DateTimeField()
    expires_at = models.DateTimeField(db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True, db_index=True)
    # Rotation chain: points to the token that replaced this one
    replaced_by = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='replaces',
    )
    created_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        verbose_name = 'refresh token'
        verbose_name_plural = 'refresh tokens'
        ordering = ['-issued_at']
        indexes = [
            models.Index(fields=['user', 'revoked_at']),
        ]

    def __str__(self):
        status = 'revoked' if self.revoked_at else 'active'
        return f'{self.user.email} - {self.jti[:8]}... ({status})'

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    @property
    def is_expired(self) -> bool:
        return timezone.now() > self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.is_revoked and not self.is_expired

    def revoke(self):
        """Mark this token as revoked."""
        if not self.revoked_at:
            self.revoked_at = timezone.now()
            self.save(update_fields=['revoked_at'])
