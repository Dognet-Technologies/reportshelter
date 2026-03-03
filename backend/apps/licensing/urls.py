from django.urls import path

from . import views

app_name = "licensing"

urlpatterns = [
    path("status/", views.LicenseStatusView.as_view(), name="status"),
    path("activate/", views.ActivateLicenseView.as_view(), name="activate"),
    path("deactivate/", views.DeactivateLicenseView.as_view(), name="deactivate"),
]
