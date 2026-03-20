from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from . import views

app_name = "accounts"

urlpatterns = [
    # Registration & email verification
    path("register/", views.RegisterView.as_view(), name="register"),
    path("verify-email/", views.VerifyEmailView.as_view(), name="verify-email"),

    # JWT
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),

    # Password management
    path("password/change/", views.PasswordChangeView.as_view(), name="password-change"),
    path("password/reset/", views.PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("password/reset/confirm/", views.PasswordResetConfirmView.as_view(), name="password-reset-confirm"),

    # Profile & organization
    path("me/", views.MeView.as_view(), name="me"),
    path("organization/", views.OrganizationView.as_view(), name="organization"),

    # User management
    path("users/", views.OrgUserListView.as_view(), name="user-list"),
    path("users/invite/", views.InviteUserView.as_view(), name="user-invite"),
    path("users/<int:pk>/", views.OrgUserDetailView.as_view(), name="user-detail"),

    # Audit log
    path("audit-log/", views.AuditLogView.as_view(), name="audit-log"),

    # System admin
    path("admin/db-stats/", views.DBStatsView.as_view(), name="db-stats"),
    path("admin/db-export/", views.DBExportView.as_view(), name="db-export"),
    path("admin/db-reset/", views.DBResetView.as_view(), name="db-reset"),
    path("admin/system-info/", views.SystemInfoView.as_view(), name="system-info"),
    path("admin/system-update/", views.SystemUpdateView.as_view(), name="system-update"),
]
