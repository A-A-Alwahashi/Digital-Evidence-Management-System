import os
from datetime import timedelta


class Config:
    """
    Central configuration for the Secure Digital Evidence Management System.

    Security goals:
    - A02: Cryptographic Failures
    - A05: Security Misconfiguration
    - A07: Identification and Authentication Failures
    - A09: Security Logging and Monitoring
    """

    SECRET_KEY = os.environ.get("SECRET_KEY")

    if not SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY is not configured. "
            "Set SECRET_KEY in the environment before starting the application."
        )

    DEBUG = False
    TESTING = False

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///instance/evidence.db"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SESSION_TYPE = "filesystem"
    SESSION_PERMANENT = True

    PERMANENT_SESSION_LIFETIME = timedelta(minutes=20)

    SESSION_COOKIE_NAME = "secure_evidence_session"

    SESSION_COOKIE_HTTPONLY = True

    SESSION_COOKIE_SECURE = (
        os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"
    )

    SESSION_COOKIE_SAMESITE = "Lax"

    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = (
        os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"
    )
    REMEMBER_COOKIE_SAMESITE = "Lax"

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    ALLOWED_EVIDENCE_EXTENSIONS = {
        "txt",
        "pdf",
        "jpg",
        "jpeg",
        "png",
        "docx",
        "xlsx",
    }

    MAX_EVIDENCE_NOTE_LENGTH = 1000

    BASE_DIR = os.path.abspath(
        os.path.dirname(os.path.dirname(__file__))
    )

    ENCRYPTED_STORAGE_DIR = os.path.join(
        BASE_DIR,
        "encrypted_storage"
    )

    KEY_DIR = os.path.join(BASE_DIR, "keys")

    PRIVATE_KEY_PATH = os.path.join(
        KEY_DIR,
        "private_key.pem"
    )

    PUBLIC_KEY_PATH = os.path.join(
        KEY_DIR,
        "public_key.pem"
    )

    AES_KEY = os.environ.get("AES_KEY")

    if not AES_KEY:
        raise RuntimeError(
            "AES_KEY is not configured. "
            "Set AES_KEY in the environment before starting the application."
        )

    MAX_FAILED_LOGIN_ATTEMPTS = 3

    ACCOUNT_LOCKOUT_MINUTES = 15

    RATELIMIT_STORAGE_URI = os.environ.get(
        "RATELIMIT_STORAGE_URI",
        "memory://"
    )

    RATELIMIT_DEFAULT = [
        "200 per day",
        "50 per hour",
    ]

    LOGIN_RATE_LIMIT = "5 per minute"

    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",

        "X-Frame-Options": "DENY",

        "Referrer-Policy": (
            "strict-origin-when-cross-origin"
        ),

        "Permissions-Policy": (
            "camera=(), "
            "microphone=(), "
            "geolocation=()"
        ),

        "Content-Security-Policy": (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        ),
    }

    LOG_DIR = os.path.join(
        BASE_DIR,
        "logs"
    )

    SECURITY_LOG_FILE = os.path.join(
        LOG_DIR,
        "security.log"
    )

    LOG_MAX_BYTES = 5 * 1024 * 1024
    LOG_BACKUP_COUNT = 5
