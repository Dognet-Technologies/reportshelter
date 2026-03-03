"""Django admin registration for the accounts app."""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import AuditLog, EmailVerificationToken, LoginAttempt, Organization, PasswordResetToken, User


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ["name", "slug", "email", "created_at"]
    search_fields = ["name", "slug", "email"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ["email", "full_name", "organization", "role", "is_email_verified", "is_active", "date_joined"]
    list_filter = ["role", "is_active", "is_email_verified", "organization"]
    search_fields = ["email", "first_name", "last_name"]
    ordering = ["email"]

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal info", {"fields": ("first_name", "last_name")}),
        ("Organization", {"fields": ("organization", "role")}),
        ("Status", {"fields": ("is_active", "is_staff", "is_superuser", "is_email_verified")}),
        ("Permissions", {"fields": ("groups", "user_permissions")}),
        ("Important dates", {"fields": ("last_login", "date_joined")}),
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "organization", "password1", "password2", "role"),
        }),
    )
    readonly_fields = ["date_joined", "last_login"]


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ["action", "user", "organization", "ip_address", "created_at"]
    list_filter = ["action", "organization"]
    search_fields = ["user__email", "action"]
    readonly_fields = ["action", "user", "organization", "detail", "ip_address", "created_at"]
    ordering = ["-created_at"]

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ["email", "ip_address", "success", "attempted_at"]
    list_filter = ["success"]
    search_fields = ["email"]
    readonly_fields = ["email", "ip_address", "success", "attempted_at"]
    ordering = ["-attempted_at"]

    def has_add_permission(self, request) -> bool:
        return False


admin.site.register(EmailVerificationToken)
admin.site.register(PasswordResetToken)
