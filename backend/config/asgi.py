"""
ASGI config for CyberReport Pro.
Supports both HTTP (Django) and WebSocket (Django Channels) connections.
"""

import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")

# Initialize Django ASGI application early to ensure apps are loaded
django_asgi_app = get_asgi_application()

from apps.notifications import routing as notifications_routing  # noqa: E402

application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        "websocket": AllowedHostsOriginValidator(
            AuthMiddlewareStack(
                URLRouter(
                    notifications_routing.websocket_urlpatterns,
                )
            )
        ),
    }
)
