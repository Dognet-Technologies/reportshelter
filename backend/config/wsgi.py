"""
WSGI config for CyberReport Pro.
Used for fallback/static serving; primary server is ASGI via Daphne.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

application = get_wsgi_application()
