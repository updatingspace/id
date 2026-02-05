import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

def read_env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}

def read_env_list(name: str, default: list[str] | None = None) -> list[str]:
    value = os.getenv(name)
    if value is None:
        return default or []
    return [item.strip() for item in value.split(",") if item.strip()]

def read_env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None:
        return default
    return value

def read_env_secret(name: str, default: str | None = None) -> str | None:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip()
    if not normalized:
        return default
    if normalized.startswith("@"):
        path = Path(normalized[1:])
        try:
            return path.read_text()
        except OSError as exc:
            raise RuntimeError(f"Cannot read secret file for {name}: {exc}") from exc
    return raw

# Security: SECRET_KEY handling
# In production (DEBUG=False), SECRET_KEY MUST be explicitly set via environment
_secret_key_default = "id-service-secret-CHANGE-ME-IN-PRODUCTION"
SECRET_KEY = read_env("DJANGO_SECRET_KEY", _secret_key_default)

DEBUG = read_env_flag("DJANGO_DEBUG", False)

# Fail fast in production if SECRET_KEY is not configured
if not DEBUG and SECRET_KEY == _secret_key_default:
    import sys
    print(
        "SECURITY ERROR: DJANGO_SECRET_KEY must be set in production. "
        "Generate a secure key with: python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'",
        file=sys.stderr,
    )
    sys.exit(1)

ALLOWED_HOSTS = read_env_list("DJANGO_ALLOWED_HOSTS", ["*"])

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites", # Required by allauth
    "corsheaders",
    
    # Internal apps
    "core",
    "accounts",
    "updspaceid",
    "idp",
    # "id.usid_service", # If needed

    # Third party
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.usersessions",
    "allauth.mfa",
    "rest_framework",
    "rest_framework_simplejwt.token_blacklist",
]

MIDDLEWARE = [
    # Correlation ID and logging context (must be first)
    "core.middleware.CorrelationIdMiddleware",
    "core.middleware.RequestLoggingMiddleware",
    # Metrics instrumentation
    "core.middleware.MetricsMiddleware",
    # Security
    "django.middleware.security.SecurityMiddleware",
    "core.middleware.SecurityHeadersMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    # Session and auth
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # User context for logging
    "core.middleware.UserContextMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

CORS_ALLOWED_ORIGINS = read_env_list(
    "CORS_ALLOWED_ORIGINS",
    ["http://localhost:5175", "http://id.localhost:5175", "http://id.localhost"],
)
CORS_ALLOW_CREDENTIALS = True
CSRF_TRUSTED_ORIGINS = read_env_list(
    "CSRF_TRUSTED_ORIGINS",
    ["http://localhost:5175", "http://id.localhost:5175", "http://id.localhost"],
)

ROOT_URLCONF = "app.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "app.wsgi.application"

import dj_database_url
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL:
    DATABASES = {
        "default": dj_database_url.config(default=DATABASE_URL, conn_max_age=600)
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

# Cache configuration (required for FormTokenService)
REDIS_URL = read_env("REDIS_URL")
if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": REDIS_URL,
        }
    }
else:
    # Fallback to database cache for single-worker dev setups
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.db.DatabaseCache",
            "LOCATION": "django_cache_table",
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 10},
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]

LANGUAGE_CODE = "en"
LANGUAGES = [
    ("en", "English"),
    ("ru", "Русский"),
]
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
MEDIA_URL = read_env("MEDIA_URL", "/media/")
MEDIA_ROOT = Path(read_env("MEDIA_ROOT", str(BASE_DIR / "media")))

SITE_ID = 1

# Allauth settings (updated for allauth 0.60+)
ACCOUNT_LOGIN_METHODS = {"email"}
ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
LOGIN_REDIRECT_URL = "/"
SOCIALACCOUNT_LOGIN_ON_GET = False

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=30),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
}

SESSION_COOKIE_SECURE = read_env_flag("SESSION_COOKIE_SECURE", True)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = read_env("SESSION_COOKIE_SAMESITE", "Strict")
CSRF_COOKIE_SECURE = read_env_flag("CSRF_COOKIE_SECURE", True)
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = read_env("CSRF_COOKIE_SAMESITE", "Strict")
SECURE_SSL_REDIRECT = read_env_flag("SECURE_SSL_REDIRECT", False)

DEFAULT_FROM_EMAIL = read_env("DEFAULT_FROM_EMAIL", "no-reply@id.localhost")
ID_PUBLIC_BASE_URL = read_env("ID_PUBLIC_BASE_URL", "http://id.localhost/api/v1")
ID_ACTIVATION_BASE_URL = read_env("ID_ACTIVATION_BASE_URL", "http://id.localhost")
ID_ACTIVATION_PATH = read_env("ID_ACTIVATION_PATH", "/activate")
MAGIC_LINK_DEFAULT_REDIRECT = read_env("MAGIC_LINK_DEFAULT_REDIRECT", "")
ID_TOKEN_HASH_SECRET = read_env("ID_TOKEN_HASH_SECRET", SECRET_KEY)

DATA_PROCESSING_CONSENT_VERSION = read_env("DATA_PROCESSING_CONSENT_VERSION", "v1")
MARKETING_CONSENT_VERSION = read_env("MARKETING_CONSENT_VERSION", "v1")
PARENTAL_CONSENT_VERSION = read_env("PARENTAL_CONSENT_VERSION", "v1")
DEVICE_FINGERPRINT_SALT = read_env("DEVICE_FINGERPRINT_SALT", "device-salt")
OIDC_ISSUER = (read_env("OIDC_ISSUER", "https://id.localhost") or "").rstrip("/")
OIDC_PUBLIC_BASE_URL = (
    read_env("OIDC_PUBLIC_BASE_URL", OIDC_ISSUER) or OIDC_ISSUER
).rstrip("/")
OIDC_REFRESH_TOKEN_SALT = read_env("OIDC_REFRESH_TOKEN_SALT", SECRET_KEY)
OIDC_AUTHORIZATION_ENDPOINT = read_env(
    "OIDC_AUTHORIZATION_ENDPOINT",
    f"{OIDC_PUBLIC_BASE_URL}/oauth/authorize",
)
OIDC_TOKEN_ENDPOINT = read_env(
    "OIDC_TOKEN_ENDPOINT",
    f"{OIDC_PUBLIC_BASE_URL}/oauth/token",
)
OIDC_USERINFO_ENDPOINT = read_env(
    "OIDC_USERINFO_ENDPOINT",
    f"{OIDC_PUBLIC_BASE_URL}/oauth/userinfo",
)
OIDC_REVOCATION_ENDPOINT = read_env(
    "OIDC_REVOCATION_ENDPOINT",
    f"{OIDC_PUBLIC_BASE_URL}/oauth/revoke",
)
OIDC_JWKS_URI = read_env(
    "OIDC_JWKS_URI",
    f"{OIDC_ISSUER}/.well-known/jwks.json",
)
OIDC_PRIVATE_KEY_PEM = read_env_secret("OIDC_PRIVATE_KEY_PEM")
OIDC_PUBLIC_KEY_PEM = read_env_secret("OIDC_PUBLIC_KEY_PEM")
OIDC_KEY_PAIRS = read_env_secret("OIDC_KEY_PAIRS")

BFF_INTERNAL_HMAC_SECRET = read_env("BFF_INTERNAL_HMAC_SECRET", "")

# External OAuth providers (link/login via external identities)
GITHUB_CLIENT_ID = read_env("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = read_env("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URIS = read_env_list("GITHUB_REDIRECT_URIS", [])
GITHUB_SCOPES = read_env_list("GITHUB_SCOPES", ["read:user"])

DISCORD_CLIENT_ID = read_env("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = read_env("DISCORD_CLIENT_SECRET", "")
DISCORD_REDIRECT_URIS = read_env_list("DISCORD_REDIRECT_URIS", [])
DISCORD_SCOPES = read_env_list("DISCORD_SCOPES", ["identify"])

STEAM_API_KEY = read_env("STEAM_API_KEY", "")
STEAM_REDIRECT_URIS = read_env_list("STEAM_REDIRECT_URIS", [])

# ============================================================================
# Production Logging Configuration
# ============================================================================
LOG_LEVEL = read_env("LOG_LEVEL", "INFO")
LOG_FORMAT = read_env("LOG_FORMAT", "json" if not DEBUG else "console")

# Email backend configuration for production
EMAIL_BACKEND = read_env(
    "EMAIL_BACKEND",
    "django.core.mail.backends.console.EmailBackend" if DEBUG else "django.core.mail.backends.smtp.EmailBackend",
)
EMAIL_HOST = read_env("EMAIL_HOST", "localhost")
EMAIL_PORT = int(read_env("EMAIL_PORT", "587") or "587")
EMAIL_HOST_USER = read_env("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = read_env_secret("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = read_env_flag("EMAIL_USE_TLS", True)
EMAIL_USE_SSL = read_env_flag("EMAIL_USE_SSL", False)

# Rate limiting configuration
RATE_LIMIT_OIDC_TOKEN = int(read_env("RATE_LIMIT_OIDC_TOKEN", "60"))  # requests per minute
RATE_LIMIT_OIDC_USERINFO = int(read_env("RATE_LIMIT_OIDC_USERINFO", "120"))  # requests per minute
RATE_LIMIT_OIDC_AUTHORIZE = int(read_env("RATE_LIMIT_OIDC_AUTHORIZE", "30"))  # requests per minute
