"""
Test settings for CyberReport Pro.

Uses SQLite in-memory so tests run without any external services
(no PostgreSQL, no Redis, no Celery worker needed).

Run with: pytest
"""

# Set env defaults BEFORE base.py imports them via python-decouple.
# These are only used during the import of base.py; test.py overrides
# DATABASES, CHANNEL_LAYERS, etc. immediately after.
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("ALLOWED_HOSTS", "localhost,127.0.0.1")
os.environ.setdefault("DB_NAME", "unused_in_tests")
os.environ.setdefault("DB_USER", "unused_in_tests")
os.environ.setdefault("DB_PASSWORD", "unused_in_tests")
os.environ.setdefault("DB_HOST", "localhost")

from .base import *  # noqa: F401, F403

DEBUG = True
ALLOWED_HOSTS = ["*"]

# --- Database: SQLite in-memory -------------------------------------------
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

# --- Django Channels: in-memory (no Redis) -----------------------------------
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    }
}

# --- Cache: in-memory (no Redis) --------------------------------------------
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

# --- Celery: run synchronously inside the test process ----------------------
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_BROKER_URL = "memory://"
CELERY_RESULT_BACKEND = "cache+memory://"

# --- Email: captured in-memory (inspect via django.core.mail.outbox) --------
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"

# --- Passwords: fast hasher speeds up tests ~10× ----------------------------
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

# --- Media files: use a temp dir --------------------------------------------
import tempfile
MEDIA_ROOT = tempfile.mkdtemp()

# --- Silence logging in tests -----------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
    "handlers": {
        "null": {"class": "logging.NullHandler"},
    },
    "root": {"handlers": ["null"], "level": "CRITICAL"},
}
