from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from django.test import TestCase, override_settings

from accounts.exceptions import (
    TokenExpiredError,
    TokenInvalidError,
    TokenTypeMismatchError,
)
from accounts.jwt import (
    create_access_token,
    create_refresh_token,
    create_token_pair,
    decode_token,
    hash_refresh_token,
)
from accounts.models import User


class JWTCreationTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email='jwt@example.com',
            password='TestPass123!@#',
        )

    def test_access_token_contains_required_claims(self):
        """Access token should contain user_id, email, token_type, iat, exp."""
        token = create_access_token(self.user)
        payload = decode_token(token)

        self.assertEqual(payload['user_id'], self.user.id)
        self.assertEqual(payload['email'], self.user.email)
        self.assertEqual(payload['token_type'], 'access')
        self.assertIn('iat', payload)
        self.assertIn('exp', payload)

    def test_refresh_token_contains_required_claims(self):
        """Refresh token should contain user_id, token_type, jti, iat, exp."""
        raw_token, jti, issued_at, expires_at = create_refresh_token(self.user)
        payload = decode_token(raw_token)

        self.assertEqual(payload['user_id'], self.user.id)
        self.assertEqual(payload['token_type'], 'refresh')
        self.assertEqual(payload['jti'], jti)
        self.assertIn('iat', payload)
        self.assertIn('exp', payload)

    def test_refresh_token_excludes_email(self):
        """Refresh token shouldn't contain email (minimize data exposure)."""
        raw_token, _, _, _ = create_refresh_token(self.user)
        payload = decode_token(raw_token)

        self.assertNotIn('email', payload)

    def test_refresh_token_returns_metadata(self):
        """create_refresh_token should return jti, issued_at, expires_at."""
        raw_token, jti, issued_at, expires_at = create_refresh_token(self.user)

        self.assertTrue(raw_token)
        self.assertTrue(len(jti) == 36)  # UUID format
        self.assertIsInstance(issued_at, datetime)
        self.assertIsInstance(expires_at, datetime)
        self.assertTrue(expires_at > issued_at)

    def test_create_token_pair_returns_both_tokens(self):
        """Token pair should contain both access and refresh tokens."""
        tokens = create_token_pair(self.user)

        self.assertIn('access_token', tokens)
        self.assertIn('refresh_token', tokens)

        # Verify they decode correctly
        access_payload = decode_token(tokens['access_token'])
        refresh_payload = decode_token(tokens['refresh_token'])

        self.assertEqual(access_payload['token_type'], 'access')
        self.assertEqual(refresh_payload['token_type'], 'refresh')


class JWTValidationTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email='validate@example.com',
            password='TestPass123!@#',
        )

    def test_valid_token_decodes_successfully(self):
        """Valid token should decode without errors."""
        token = create_access_token(self.user)
        payload = decode_token(token)

        self.assertEqual(payload['user_id'], self.user.id)

    def test_tampered_token_raises_invalid_error(self):
        """Modified token should fail signature verification."""
        token = create_access_token(self.user)
        tampered = token[:-5] + 'XXXXX'

        with self.assertRaises(TokenInvalidError):
            decode_token(tampered)

    def test_garbage_token_raises_invalid_error(self):
        """Random string should raise TokenInvalidError."""
        with self.assertRaises(TokenInvalidError):
            decode_token('not.a.valid.jwt.token')

    def test_expired_token_raises_expired_error(self):
        """Expired token should raise TokenExpiredError."""
        with patch('accounts.jwt.datetime') as mock_dt:
            mock_dt.now.return_value = datetime.now(timezone.utc) - timedelta(hours=1)
            mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)
            token = create_access_token(self.user)

        with self.assertRaises(TokenExpiredError):
            decode_token(token)

    def test_type_validation_accepts_correct_type(self):
        """Specifying correct expected_type should pass."""
        token = create_access_token(self.user)
        payload = decode_token(token, expected_type='access')

        self.assertEqual(payload['token_type'], 'access')

    def test_type_validation_rejects_wrong_type(self):
        """Using refresh token where access expected should raise error."""
        raw_token, _, _, _ = create_refresh_token(self.user)

        with self.assertRaises(TokenTypeMismatchError):
            decode_token(raw_token, expected_type='access')

    def test_access_token_rejected_as_refresh(self):
        """Using access token where refresh expected should raise error."""
        access_token = create_access_token(self.user)

        with self.assertRaises(TokenTypeMismatchError):
            decode_token(access_token, expected_type='refresh')


class JWTHashingTests(TestCase):

    def test_hash_is_deterministic(self):
        """Same token should produce same hash."""
        token = 'test.jwt.token'
        hash1 = hash_refresh_token(token)
        hash2 = hash_refresh_token(token)

        self.assertEqual(hash1, hash2)

    def test_hash_is_64_chars(self):
        """SHA-256 hex digest should be 64 characters."""
        token = 'test.jwt.token'
        token_hash = hash_refresh_token(token)

        self.assertEqual(len(token_hash), 64)

    def test_different_tokens_produce_different_hashes(self):
        """Different tokens should produce different hashes."""
        hash1 = hash_refresh_token('token1')
        hash2 = hash_refresh_token('token2')

        self.assertNotEqual(hash1, hash2)


@override_settings(JWT_ACCESS_TOKEN_LIFETIME=60, JWT_REFRESH_TOKEN_LIFETIME=120)
class JWTLifetimeTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email='lifetime@example.com',
            password='TestPass123!@#',
        )

    def test_access_token_respects_configured_lifetime(self):
        """Access token expiration should match settings."""
        token = create_access_token(self.user)
        payload = decode_token(token)

        lifetime = payload['exp'] - payload['iat']
        self.assertAlmostEqual(lifetime, 60, delta=1)

    def test_refresh_token_respects_configured_lifetime(self):
        """Refresh token expiration should match settings."""
        raw_token, _, _, _ = create_refresh_token(self.user)
        payload = decode_token(raw_token)

        lifetime = payload['exp'] - payload['iat']
        self.assertAlmostEqual(lifetime, 120, delta=1)
