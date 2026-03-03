"""
Development settings for CyberReport Pro.
"""

from .base import *  # noqa: F401, F403

DEBUG = True

# Allow all hosts in dev
ALLOWED_HOSTS = ["*"]

# CORS — allow Vite dev server
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:80",
]
CORS_ALLOW_CREDENTIALS = True

# Email — console backend in dev
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# Django Debug Toolbar (optional, add to requirements if needed)
# INSTALLED_APPS += ["debug_toolbar"]

# Celery — run tasks eagerly in dev for easier debugging (comment out for real async)
# CELERY_TASK_ALWAYS_EAGER = True

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "DEBUG",
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "apps": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
        "celery": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
