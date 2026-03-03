"""Django admin for the licensing app."""

from django.contrib import admin

from .models import License


@admin.register(License)
class LicenseAdmin(admin.ModelAdmin):
    list_display = ["organization", "status", "license_key", "trial_expires_at", "pro_expires_at", "updated_at"]
    list_filter = ["status"]
    search_fields = ["organization__name", "license_key"]
    readonly_fields = ["created_at", "updated_at", "last_checked_at"]
    actions = ["force_expire"]

    @admin.action(description="Force expire selected licenses")
    def force_expire(self, request, queryset):
        from django.utils import timezone
        queryset.update(trial_expires_at=timezone.now(), pro_expires_at=timezone.now())
        self.message_user(request, "Selected licenses have been expired.")
