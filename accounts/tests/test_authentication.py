from django.test import TestCase, override_settings

from accounts.models import AuthenticationEvent, LoginAttempt, User
from accounts.services import authenticate_user


class MockRequest:
    """Minimal request mock for testing."""

    def __init__(self, ip='192.168.1.1', user_agent='TestAgent'):
        self.META = {
            'REMOTE_ADDR': ip,
            'HTTP_USER_AGENT': user_agent,
        }


class AuthenticationTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='SecurePass123!@#',
        )
        # Clear any existing attempts
        LoginAttempt.objects.all().delete()

    def test_successful_login(self):
        """Valid credentials should authenticate successfully."""
        request = MockRequest()
        result = authenticate_user(request, 'test@example.com', 'SecurePass123!@#')

        self.assertTrue(result.success)
        self.assertEqual(result.user, self.user)
        self.assertEqual(result.error, '')

        # Verify audit log
        event = AuthenticationEvent.objects.latest('timestamp')
        self.assertEqual(event.event_type, AuthenticationEvent.EventType.LOGIN_SUCCESS)
        self.assertEqual(event.user, self.user)

    def test_failed_login_wrong_password(self):
        """Wrong password should fail with generic message."""
        request = MockRequest()
        result = authenticate_user(request, 'test@example.com', 'WrongPassword123')

        self.assertFalse(result.success)
        self.assertIsNone(result.user)
        self.assertEqual(result.error, 'Invalid credentials.')

        # Verify audit log
        event = AuthenticationEvent.objects.latest('timestamp')
        self.assertEqual(event.event_type, AuthenticationEvent.EventType.LOGIN_FAILED)

    def test_failed_login_nonexistent_user(self):
        """
        Non-existent user should return same error as wrong password.
        Prevents user enumeration attacks.
        """
        request = MockRequest()
        result = authenticate_user(request, 'nobody@example.com', 'SomePassword123')

        self.assertFalse(result.success)
        self.assertEqual(result.error, 'Invalid credentials.')

    def test_inactive_user_returns_generic_error(self):
        """
        Inactive users should get same error message.
        Prevents account status enumeration.
        """
        self.user.is_active = False
        self.user.save()

        request = MockRequest()
        result = authenticate_user(request, 'test@example.com', 'SecurePass123!@#')

        self.assertFalse(result.success)
        self.assertEqual(result.error, 'Invalid credentials.')


@override_settings(
    AUTH_MAX_ATTEMPTS=3,
    AUTH_LOCKOUT_DURATION=900,
    AUTH_ATTEMPT_WINDOW=900,
)
class BruteForceProtectionTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            email='victim@example.com',
            password='VictimPass123!@#',
        )
        LoginAttempt.objects.all().delete()
        AuthenticationEvent.objects.all().delete()

    def test_account_locks_after_max_attempts(self):
        """Account should lock after configured max failed attempts."""
        request = MockRequest()

        # Fail 3 times (max attempts)
        for _ in range(3):
            result = authenticate_user(request, 'victim@example.com', 'WrongPass')
            self.assertFalse(result.success)

        # Next attempt should be locked
        result = authenticate_user(request, 'victim@example.com', 'WrongPass')
        self.assertTrue(result.locked)
        self.assertIn('locked', result.error.lower())

    def test_locked_account_blocks_correct_password(self):
        """Even correct password should fail during lockout."""
        request = MockRequest()

        # Trigger lockout
        for _ in range(3):
            authenticate_user(request, 'victim@example.com', 'WrongPass')

        # Correct password should still fail
        result = authenticate_user(request, 'victim@example.com', 'VictimPass123!@#')
        self.assertFalse(result.success)
        self.assertTrue(result.locked)

    def test_ip_based_lockout(self):
        """IP should be locked after max attempts across different emails."""
        request = MockRequest(ip='10.0.0.1')

        # Attack multiple emails from same IP
        for i in range(3):
            authenticate_user(request, f'target{i}@example.com', 'WrongPass')

        # Same IP attacking new email should be locked
        result = authenticate_user(request, 'newvictim@example.com', 'WrongPass')
        self.assertTrue(result.locked)

    def test_different_ip_not_affected(self):
        """Failed attempts from one IP shouldn't affect another."""
        attacker_request = MockRequest(ip='10.0.0.1')
        legit_request = MockRequest(ip='10.0.0.2')

        # Attacker fails 3 times
        for _ in range(3):
            authenticate_user(attacker_request, 'victim@example.com', 'WrongPass')

        # Legitimate user from different IP should work
        result = authenticate_user(legit_request, 'victim@example.com', 'VictimPass123!@#')
        self.assertTrue(result.success)

    def test_successful_login_clears_email_attempts(self):
        """Successful login should clear failed attempt count for that email+IP."""
        request = MockRequest()

        # Fail twice (not enough for lockout)
        authenticate_user(request, 'victim@example.com', 'WrongPass')
        authenticate_user(request, 'victim@example.com', 'WrongPass')

        # Successful login
        result = authenticate_user(request, 'victim@example.com', 'VictimPass123!@#')
        self.assertTrue(result.success)

        # Check attempts were cleared for email+IP pair
        email_ip_key = f'victim@example.com:{request.META["REMOTE_ADDR"]}'
        email_attempts = LoginAttempt.objects.filter(
            identifier=email_ip_key,
            identifier_type='email_ip',
        ).count()
        self.assertEqual(email_attempts, 0)

    def test_lockout_event_logged(self):
        """Lockout should be logged as ACCOUNT_LOCKED event."""
        request = MockRequest()

        # Trigger lockout
        for _ in range(3):
            authenticate_user(request, 'victim@example.com', 'WrongPass')

        # One more to trigger locked response
        authenticate_user(request, 'victim@example.com', 'WrongPass')

        # Verify ACCOUNT_LOCKED event exists
        locked_events = AuthenticationEvent.objects.filter(
            event_type=AuthenticationEvent.EventType.ACCOUNT_LOCKED,
        )
        self.assertTrue(locked_events.exists())

