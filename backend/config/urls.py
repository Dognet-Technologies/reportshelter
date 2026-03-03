"""
Root URL configuration for CyberReport Pro API.
"""

from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static

api_v1_patterns = [
    path("auth/", include("apps.accounts.urls")),
    path("licensing/", include("apps.licensing.urls")),
    path("projects/", include("apps.projects.urls")),
    path("vulnerabilities/", include("apps.vulnerabilities.urls")),
    path("parsers/", include("apps.parsers.urls")),
    path("reports/", include("apps.reports.urls")),
]

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/", include(api_v1_patterns)),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
