import json

from django.conf import settings
from django.test import Client, TestCase, override_settings

from accounts.models import AuthenticationEvent, RefreshToken, User
from accounts.services import create_token_pair_for_user


@override_settings(
    REFRESH_TOKEN_COOKIE_NAME='refresh_token',
    REFRESH_TOKEN_COOKIE_PATH='/api/auth/',
)
class CookieAuthTests(TestCase):

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.user = User.objects.create_user(
            email='cookie@example.com',
            password='CookiePass123!@#',
        )
        RefreshToken.objects.all().delete()

    def _login(self):
        """Helper to login and get tokens."""
        response = self.client.post(
            '/api/auth/login/',
            data=json.dumps({
                'email': 'cookie@example.com',
                'password': 'CookiePass123!@#',
            }),
            content_type='application/json',
        )
        return response

    def _get_csrf_token(self):
        """Get CSRF token from endpoint."""
        response = self.client.get('/api/auth/csrf/')
        data = json.loads(response.content)
        return data.get('csrfToken'), response.cookies.get('csrftoken')

    def test_login_sets_refresh_cookie(self):
        """Login should set refresh token as HttpOnly cookie."""
        response = self._login()

        self.assertEqual(response.status_code, 200)
        self.assertIn('refresh_token', response.cookies)

        cookie = response.cookies['refresh_token']
        self.assertTrue(cookie['httponly'])
        self.assertEqual(cookie['path'], '/api/auth/')

    def test_login_returns_only_access_token_in_json(self):
        """Login JSON should contain only access token, not refresh."""
        response = self._login()
        data = json.loads(response.content)

        self.assertIn('access_token', data)
        self.assertNotIn('refresh_token', data)

    def test_refresh_with_valid_csrf_works(self):
        """Refresh should succeed with valid CSRF token and cookie."""
        # Login first
        login_response = self._login()
        self.assertEqual(login_response.status_code, 200)

        # Get CSRF token
        csrf_token, _ = self._get_csrf_token()

        # Refresh with CSRF header
        response = self.client.post(
            '/api/auth/refresh/',
            content_type='application/json',
            HTTP_X_CSRFTOKEN=csrf_token,
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn('access_token', data)

    def test_refresh_without_csrf_fails(self):
        """Refresh should fail without CSRF token."""
        # Login first
        self._login()

        # Try refresh without CSRF
        response = self.client.post(
            '/api/auth/refresh/',
            content_type='application/json',
        )

        self.assertEqual(response.status_code, 403)

    def test_refresh_without_cookie_fails(self):
        """Refresh should fail if no refresh cookie present."""
        csrf_token, _ = self._get_csrf_token()

        # Clear cookies
        self.client.cookies.clear()

        # Get new CSRF (needed after clearing cookies)
        csrf_token, _ = self._get_csrf_token()

        response = self.client.post(
            '/api/auth/refresh/',
            content_type='application/json',
            HTTP_X_CSRFTOKEN=csrf_token,
        )

        self.assertEqual(response.status_code, 401)
        data = json.loads(response.content)
        self.assertIn('not found', data['error'].lower())

    def test_logout_clears_cookie(self):
        """Logout should clear the refresh cookie."""
        # Login first
        login_response = self._login()
        self.assertIn('refresh_token', login_response.cookies)

        # Get CSRF token
        csrf_token, _ = self._get_csrf_token()

        # Logout
        response = self.client.post(
            '/api/auth/logout/',
            content_type='application/json',
            HTTP_X_CSRFTOKEN=csrf_token,
        )

        self.assertEqual(response.status_code, 200)
        # Cookie should be set to expire
        self.assertIn('refresh_token', response.cookies)
        self.assertEqual(response.cookies['refresh_token']['max-age'], 0)

    def test_token_rotation_updates_cookie(self):
        """Refresh should set new refresh token cookie."""
        # Login
        login_response = self._login()
        old_cookie = login_response.cookies['refresh_token'].value

        # Get CSRF
        csrf_token, _ = self._get_csrf_token()

        # Refresh
        response = self.client.post(
            '/api/auth/refresh/',
            content_type='application/json',
            HTTP_X_CSRFTOKEN=csrf_token,
        )

        self.assertEqual(response.status_code, 200)
        new_cookie = response.cookies['refresh_token'].value
        self.assertNotEqual(old_cookie, new_cookie)

    def test_csrf_endpoint_returns_token(self):
        """CSRF endpoint should return token in JSON."""
        response = self.client.get('/api/auth/csrf/')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn('csrfToken', data)
        self.assertTrue(len(data['csrfToken']) > 0)


@override_settings(
    REFRESH_TOKEN_COOKIE_NAME='refresh_token',
    REFRESH_TOKEN_COOKIE_PATH='/api/auth/',
)
class CookieTokenReuseTests(TestCase):
    """Ensure token reuse detection still works with cookies."""

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)
        self.user = User.objects.create_user(
            email='reuse@example.com',
            password='ReusePass123!@#',
        )
        RefreshToken.objects.all().delete()
        AuthenticationEvent.objects.all().delete()

    def test_reuse_detection_works_with_cookies(self):
        """Token reuse should trigger detection even with cookie-based auth."""
        # Login
        login_response = self.client.post(
            '/api/auth/login/',
            data=json.dumps({
                'email': 'reuse@example.com',
                'password': 'ReusePass123!@#',
            }),
            content_type='application/json',
        )
        old_refresh_cookie = login_response.cookies['refresh_token'].value

        # Get CSRF and do first refresh
        csrf_response = self.client.get('/api/auth/csrf/')
        csrf_token = json.loads(csrf_response.content)['csrfToken']

        self.client.post(
            '/api/auth/refresh/',
            content_type='application/json',
            HTTP_X_CSRFTOKEN=csrf_token,
        )

        # Manually set old cookie to simulate attacker reusing stolen token
        self.client.cookies['refresh_token'] = old_refresh_cookie

        # Get fresh CSRF for "attacker"
        csrf_response = self.client.get('/api/auth/csrf/')
        csrf_token = json.loads(csrf_response.content)['csrfToken']

        # Try to reuse old token
        response = self.client.post(
            '/api/auth/refresh/',
            content_type='application/json',
            HTTP_X_CSRFTOKEN=csrf_token,
        )

        self.assertEqual(response.status_code, 401)

        # Check reuse event logged
        reuse_events = AuthenticationEvent.objects.filter(
            event_type=AuthenticationEvent.EventType.TOKEN_REUSE_DETECTED,
        )
        self.assertTrue(reuse_events.exists())

        # All tokens should be revoked
        active = RefreshToken.objects.filter(
            user=self.user,
            revoked_at__isnull=True,
        ).count()
        self.assertEqual(active, 0)

