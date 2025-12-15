import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY: Always use environment variable in production
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-insecure-key-change-in-production')

DEBUG = os.environ.get('DEBUG', 'True').lower() in ('true', '1', 'yes')

ALLOWED_HOSTS = [
    host.strip()
    for host in os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
    if host.strip()
]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'accounts',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# =============================================================================
# SECURITY BASELINE
# =============================================================================

# Trust X-Forwarded-Proto header from reverse proxy (nginx, load balancer)
# Required when running behind HTTPS-terminating proxy
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Cookie security: enforce HTTPS-only in production
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG

# Prevent JavaScript access to session cookie (mitigates XSS token theft)
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

# SameSite=Lax: cookies sent on top-level navigations and GET from external sites
# Balances CSRF protection with usability (strict would break OAuth redirects)
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'

# Prevent MIME type sniffing attacks
SECURE_CONTENT_TYPE_NOSNIFF = True

# Clickjacking protection: deny all framing
X_FRAME_OPTIONS = 'DENY'

# Referrer policy: only send origin to same-origin requests
SECURE_REFERRER_POLICY = 'same-origin'

# SECURE_BROWSER_XSS_FILTER is deprecated in Django 4+ and modern browsers
# X-XSS-Protection header is now considered harmful; CSP is the proper solution

# =============================================================================
# BRUTE-FORCE PROTECTION
# =============================================================================

# Max failed attempts before temporary lockout
AUTH_MAX_ATTEMPTS = int(os.environ.get('AUTH_MAX_ATTEMPTS', '5'))

# Lockout duration in seconds (default: 15 minutes)
AUTH_LOCKOUT_DURATION = int(os.environ.get('AUTH_LOCKOUT_DURATION', '900'))

# Time window for counting failed attempts (default: 15 minutes)
AUTH_ATTEMPT_WINDOW = int(os.environ.get('AUTH_ATTEMPT_WINDOW', '900'))

# =============================================================================
# JWT CONFIGURATION
# =============================================================================

# Access token: short-lived for API requests (default: 10 minutes)
JWT_ACCESS_TOKEN_LIFETIME = int(os.environ.get('JWT_ACCESS_TOKEN_LIFETIME', '600'))

# Refresh token: long-lived for obtaining new access tokens (default: 7 days)
JWT_REFRESH_TOKEN_LIFETIME = int(os.environ.get('JWT_REFRESH_TOKEN_LIFETIME', '604800'))

# =============================================================================
# REFRESH TOKEN COOKIE
# =============================================================================

REFRESH_TOKEN_COOKIE_NAME = 'refresh_token'

# HttpOnly: JavaScript cannot access this cookie (XSS protection)
REFRESH_TOKEN_COOKIE_HTTPONLY = True

# Secure: only sent over HTTPS in production
REFRESH_TOKEN_COOKIE_SECURE = not DEBUG

# SameSite=Lax: protects against CSRF while allowing top-level navigation
# Strict would break redirects; None requires Secure and allows cross-site
REFRESH_TOKEN_COOKIE_SAMESITE = 'Lax'

# Path: cookie only sent to auth endpoints (minimizes exposure)
REFRESH_TOKEN_COOKIE_PATH = '/api/auth/'

# =============================================================================
# CSRF CONFIGURATION
# =============================================================================

# For production with custom domain, add to CSRF_TRUSTED_ORIGINS:
# CSRF_TRUSTED_ORIGINS = ['https://yourdomain.com']

# =============================================================================
# PASSWORD HASHING
# =============================================================================

# Argon2 preferred for memory-hard protection against GPU/ASIC attacks
# PBKDF2 as fallback for environments without argon2-cffi
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
    'django.contrib.auth.hashers.ScryptPasswordHasher',
]

# =============================================================================
# PASSWORD POLICY
# =============================================================================

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 12},
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# =============================================================================
# INTERNATIONALIZATION
# =============================================================================

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Baku'

USE_I18N = True

USE_TZ = True

# =============================================================================
# STATIC FILES
# =============================================================================

STATIC_URL = 'static/'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

AUTH_USER_MODEL = 'accounts.User'
