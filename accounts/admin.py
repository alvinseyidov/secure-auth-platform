from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils import timezone

from .models import AuthenticationEvent, RefreshToken, User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin configuration for custom User model."""

    list_display = ('email', 'is_staff', 'is_active', 'date_joined')
    list_filter = ('is_staff', 'is_active')
    search_fields = ('email',)
    ordering = ('-date_joined',)

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Dates', {'fields': ('date_joined', 'last_login')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'is_staff', 'is_active'),
        }),
    )

    readonly_fields = ('date_joined', 'last_login')


@admin.register(AuthenticationEvent)
class AuthenticationEventAdmin(admin.ModelAdmin):
    """
    Read-only admin for authentication audit logs.
    Audit logs must be immutable for forensic integrity.
    """

    list_display = ('timestamp', 'event_type', 'email_attempted', 'ip_address', 'user')
    list_filter = ('event_type', 'timestamp')
    search_fields = ('email_attempted', 'ip_address')
    ordering = ('-timestamp',)
    date_hierarchy = 'timestamp'

    readonly_fields = (
        'user',
        'email_attempted',
        'ip_address',
        'event_type',
        'user_agent',
        'timestamp',
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    """
    Mostly read-only admin for refresh tokens.
    Allows superusers to revoke tokens for security response.
    """

    list_display = ('user', 'jti_short', 'issued_at', 'expires_at', 'status', 'created_ip')
    list_filter = ('revoked_at', 'issued_at')
    search_fields = ('user__email', 'jti', 'created_ip')
    ordering = ('-issued_at',)
    date_hierarchy = 'issued_at'
    raw_id_fields = ('user', 'replaced_by')

    readonly_fields = (
        'user',
        'token_hash',
        'jti',
        'issued_at',
        'expires_at',
        'replaced_by',
        'created_ip',
        'user_agent',
    )

    def jti_short(self, obj):
        """Display truncated jti for readability."""
        return f'{obj.jti[:8]}...'
    jti_short.short_description = 'Token ID'

    def status(self, obj):
        """Display token status."""
        if obj.is_revoked:
            return 'Revoked'
        if obj.is_expired:
            return 'Expired'
        return 'Active'
    status.short_description = 'Status'

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser

    actions = ['revoke_tokens']

    @admin.action(description='Revoke selected tokens')
    def revoke_tokens(self, request, queryset):
        """Admin action to revoke selected tokens."""
        count = queryset.filter(revoked_at__isnull=True).update(
            revoked_at=timezone.now()
        )
        self.message_user(request, f'{count} token(s) revoked.')
