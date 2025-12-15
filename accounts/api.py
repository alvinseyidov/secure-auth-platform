"""
Authentication API endpoints.
Thin views that delegate to service layer.
"""
import json

from django.conf import settings
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.views import View
from django.views.decorators.csrf import csrf_exempt, csrf_protect, ensure_csrf_cookie
from django.utils.decorators import method_decorator

from .services import (
    authenticate_user,
    create_token_pair_for_user,
    get_client_ip,
    revoke_refresh_token,
    rotate_refresh_token,
)


def _parse_json_body(request):
    """Parse JSON request body, return dict or None."""
    try:
        return json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return None


def _get_cookie_settings():
    """Get refresh token cookie settings."""
    return {
        'key': getattr(settings, 'REFRESH_TOKEN_COOKIE_NAME', 'refresh_token'),
        'httponly': getattr(settings, 'REFRESH_TOKEN_COOKIE_HTTPONLY', True),
        'secure': getattr(settings, 'REFRESH_TOKEN_COOKIE_SECURE', True),
        'samesite': getattr(settings, 'REFRESH_TOKEN_COOKIE_SAMESITE', 'Lax'),
        'path': getattr(settings, 'REFRESH_TOKEN_COOKIE_PATH', '/api/auth/'),
    }


def _set_refresh_cookie(response, refresh_token: str, max_age: int = None):
    """Set the refresh token cookie on a response."""
    cookie = _get_cookie_settings()
    if max_age is None:
        max_age = getattr(settings, 'JWT_REFRESH_TOKEN_LIFETIME', 604800)

    response.set_cookie(
        key=cookie['key'],
        value=refresh_token,
        max_age=max_age,
        httponly=cookie['httponly'],
        secure=cookie['secure'],
        samesite=cookie['samesite'],
        path=cookie['path'],
    )


def _clear_refresh_cookie(response):
    """Clear the refresh token cookie."""
    cookie = _get_cookie_settings()
    response.delete_cookie(
        key=cookie['key'],
        path=cookie['path'],
        samesite=cookie['samesite'],
    )


def _get_refresh_token_from_cookie(request) -> str:
    """Extract refresh token from HttpOnly cookie."""
    cookie_name = getattr(settings, 'REFRESH_TOKEN_COOKIE_NAME', 'refresh_token')
    return request.COOKIES.get(cookie_name, '')


@method_decorator(csrf_exempt, name='dispatch')
class LoginView(View):
    """
    POST /api/auth/login/
    
    Authenticate with email/password.
    Returns access token in JSON, sets refresh token as HttpOnly cookie.
    
    CSRF exempt: login uses credentials, not session state.
    """

    def post(self, request):
        data = _parse_json_body(request)
        if not data:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        email = data.get('email', '').strip()
        password = data.get('password', '')

        if not email or not password:
            return JsonResponse({'error': 'Email and password required'}, status=400)

        result = authenticate_user(request, email, password)

        if not result.success:
            status = 423 if result.locked else 401
            return JsonResponse({'error': result.error}, status=status)

        ip = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        tokens = create_token_pair_for_user(result.user, ip, user_agent)

        response = JsonResponse({
            'access_token': tokens.access_token,
        })
        _set_refresh_cookie(response, tokens.refresh_token)

        return response


@method_decorator(csrf_protect, name='dispatch')
class RefreshView(View):
    """
    POST /api/auth/refresh/
    
    Exchange refresh token (from cookie) for new token pair.
    
    CSRF protected: uses cookie-based auth, vulnerable to CSRF without protection.
    Frontend must send X-CSRFToken header obtained from /api/auth/csrf/.
    """

    def post(self, request):
        refresh_token = _get_refresh_token_from_cookie(request)

        if not refresh_token:
            return JsonResponse({'error': 'Refresh token not found'}, status=401)

        ip = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        result = rotate_refresh_token(refresh_token, ip, user_agent)

        if not result.success:
            response = JsonResponse({'error': result.error}, status=401)
            _clear_refresh_cookie(response)
            return response

        response = JsonResponse({
            'access_token': result.access_token,
        })
        _set_refresh_cookie(response, result.refresh_token)

        return response


@method_decorator(csrf_protect, name='dispatch')
class LogoutView(View):
    """
    POST /api/auth/logout/
    
    Revoke refresh token and clear cookie.
    
    CSRF protected: prevents malicious sites from logging out users.
    """

    def post(self, request):
        refresh_token = _get_refresh_token_from_cookie(request)

        if refresh_token:
            revoke_refresh_token(refresh_token)

        response = JsonResponse({'message': 'Logged out successfully'})
        _clear_refresh_cookie(response)

        return response


@method_decorator(ensure_csrf_cookie, name='dispatch')
class CSRFTokenView(View):
    """
    GET /api/auth/csrf/
    
    Returns CSRF token for frontend to use in subsequent requests.
    Sets CSRF cookie if not already present.
    """

    def get(self, request):
        return JsonResponse({
            'csrfToken': get_token(request),
        })
