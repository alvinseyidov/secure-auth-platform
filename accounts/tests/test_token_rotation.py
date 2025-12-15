from django.test import TestCase, override_settings

from accounts.jwt import decode_token, hash_refresh_token
from accounts.models import AuthenticationEvent, RefreshToken, User
from accounts.services import (
    create_token_pair_for_user,
    revoke_refresh_token,
    rotate_refresh_token,
)


class TokenCreationTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email='tokens@example.com',
            password='TokenPass123!@#',
        )

    def test_login_creates_refresh_token_in_db(self):
        """Login should persist refresh token hash to database."""
        result = create_token_pair_for_user(self.user, '192.168.1.1', 'TestAgent')

        self.assertTrue(result.success)
        self.assertTrue(result.access_token)
        self.assertTrue(result.refresh_token)

        # Verify DB entry exists
        token_hash = hash_refresh_token(result.refresh_token)
        self.assertTrue(
            RefreshToken.objects.filter(
                user=self.user,
                token_hash=token_hash,
            ).exists()
        )

    def test_refresh_token_contains_jti(self):
        """Refresh token should contain jti claim."""
        result = create_token_pair_for_user(self.user)
        payload = decode_token(result.refresh_token, expected_type='refresh')

        self.assertIn('jti', payload)
        self.assertTrue(len(payload['jti']) > 0)


class TokenRotationTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email='rotate@example.com',
            password='RotatePass123!@#',
        )
        RefreshToken.objects.all().delete()

    def test_rotation_returns_new_tokens(self):
        """Rotation should return new access and refresh tokens."""
        # Create initial tokens
        initial = create_token_pair_for_user(self.user)

        # Rotate
        result = rotate_refresh_token(initial.refresh_token, '10.0.0.1')

        self.assertTrue(result.success)
        self.assertTrue(result.access_token)
        self.assertTrue(result.refresh_token)
        # New tokens should be different
        self.assertNotEqual(result.refresh_token, initial.refresh_token)

    def test_rotation_revokes_old_token(self):
        """Old refresh token should be marked as revoked after rotation."""
        initial = create_token_pair_for_user(self.user)
        old_hash = hash_refresh_token(initial.refresh_token)

        rotate_refresh_token(initial.refresh_token)

        old_token = RefreshToken.objects.get(token_hash=old_hash)
        self.assertTrue(old_token.is_revoked)

    def test_rotation_links_old_to_new(self):
        """Old token should have replaced_by pointing to new token."""
        initial = create_token_pair_for_user(self.user)
        old_hash = hash_refresh_token(initial.refresh_token)

        result = rotate_refresh_token(initial.refresh_token)
        new_hash = hash_refresh_token(result.refresh_token)

        old_token = RefreshToken.objects.get(token_hash=old_hash)
        new_token = RefreshToken.objects.get(token_hash=new_hash)

        self.assertEqual(old_token.replaced_by, new_token)

    def test_new_token_works_after_rotation(self):
        """New refresh token from rotation should be usable."""
        initial = create_token_pair_for_user(self.user)
        first_rotation = rotate_refresh_token(initial.refresh_token)

        # Use the new token
        second_rotation = rotate_refresh_token(first_rotation.refresh_token)

        self.assertTrue(second_rotation.success)


class TokenReuseDetectionTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email='reuse@example.com',
            password='ReusePass123!@#',
        )
        RefreshToken.objects.all().delete()
        AuthenticationEvent.objects.all().delete()

    def test_reusing_revoked_token_fails(self):
        """Using an already-rotated token should fail."""
        initial = create_token_pair_for_user(self.user)

        # First rotation succeeds
        rotate_refresh_token(initial.refresh_token)

        # Second use of same token should fail
        result = rotate_refresh_token(initial.refresh_token)

        self.assertFalse(result.success)
        self.assertIn('revoked', result.error.lower())

    def test_token_reuse_revokes_all_user_tokens(self):
        """Token reuse attack should revoke ALL user's tokens."""
        initial = create_token_pair_for_user(self.user)

        # Create a second valid token
        second = create_token_pair_for_user(self.user)

        # Rotate first token
        new_from_first = rotate_refresh_token(initial.refresh_token)

        # Attacker tries to reuse the old first token
        rotate_refresh_token(initial.refresh_token)

        # All tokens should now be revoked
        active_count = RefreshToken.objects.filter(
            user=self.user,
            revoked_at__isnull=True,
        ).count()
        self.assertEqual(active_count, 0)

    def test_token_reuse_logs_security_event(self):
        """Token reuse should log TOKEN_REUSE_DETECTED event."""
        initial = create_token_pair_for_user(self.user)

        rotate_refresh_token(initial.refresh_token)
        rotate_refresh_token(initial.refresh_token, '192.168.1.1')

        events = AuthenticationEvent.objects.filter(
            event_type=AuthenticationEvent.EventType.TOKEN_REUSE_DETECTED,
            user=self.user,
        )
        self.assertTrue(events.exists())


class TokenRevocationTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email='revoke@example.com',
            password='RevokePass123!@#',
        )
        RefreshToken.objects.all().delete()

    def test_logout_revokes_token(self):
        """Logout should revoke the provided refresh token."""
        tokens = create_token_pair_for_user(self.user)
        token_hash = hash_refresh_token(tokens.refresh_token)

        result = revoke_refresh_token(tokens.refresh_token)

        self.assertTrue(result)

        stored = RefreshToken.objects.get(token_hash=token_hash)
        self.assertTrue(stored.is_revoked)

    def test_revoked_token_cannot_rotate(self):
        """Revoked token should not be usable for rotation."""
        tokens = create_token_pair_for_user(self.user)

        # Logout
        revoke_refresh_token(tokens.refresh_token)

        # Try to use revoked token
        result = rotate_refresh_token(tokens.refresh_token)

        self.assertFalse(result.success)

    def test_logout_with_invalid_token_returns_false(self):
        """Logout with garbage token should return False."""
        result = revoke_refresh_token('not.a.valid.token')
        self.assertFalse(result)

