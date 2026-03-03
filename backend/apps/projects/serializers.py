"""
Serializers for the projects app.
"""

from django.contrib.auth import get_user_model
from rest_framework import serializers

from apps.accounts.serializers import UserSerializer

from .models import Project, ProjectLock, ProjectMembership, Screenshot, SubProject


class ProjectMembershipSerializer(serializers.ModelSerializer):
    """Serializer for project memberships."""

    user = UserSerializer(read_only=True)
    user_id = serializers.PrimaryKeyRelatedField(
        source="user",
        queryset=get_user_model().objects.all(),
        write_only=True,
    )

    class Meta:
        model = ProjectMembership
        fields = ["id", "user", "user_id", "added_at"]
        read_only_fields = ["id", "added_at"]


class SubProjectSerializer(serializers.ModelSerializer):
    """Serializer for SubProject — list and detail."""

    vulnerability_count = serializers.IntegerField(read_only=True, default=0)

    class Meta:
        model = SubProject
        fields = [
            "id",
            "project",
            "title",
            "description",
            "scan_date",
            "vulnerability_count",
            "created_by",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "project", "created_by", "created_at", "updated_at"]


class SubProjectWriteSerializer(serializers.ModelSerializer):
    """Write-only serializer for creating/updating SubProjects."""

    class Meta:
        model = SubProject
        fields = ["title", "description", "scan_date"]


class ProjectLockSerializer(serializers.ModelSerializer):
    """Serializer for ProjectLock status."""

    locked_by_name = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()

    class Meta:
        model = ProjectLock
        fields = ["locked_by", "locked_by_name", "locked_at", "last_heartbeat", "is_expired"]
        read_only_fields = fields

    def get_locked_by_name(self, obj: ProjectLock) -> str:
        if obj.locked_by:
            return obj.locked_by.full_name
        return ""

    def get_is_expired(self, obj: ProjectLock) -> bool:
        return obj.is_expired()


class ScreenshotSerializer(serializers.ModelSerializer):
    """Serializer for screenshots."""

    class Meta:
        model = Screenshot
        fields = [
            "id",
            "subproject",
            "vulnerability_ref",
            "image",
            "caption",
            "order",
            "uploaded_by",
            "uploaded_at",
        ]
        read_only_fields = ["id", "subproject", "uploaded_by", "uploaded_at"]


class ProjectListSerializer(serializers.ModelSerializer):
    """Compact serializer for project listings."""

    subproject_count = serializers.IntegerField(read_only=True, default=0)
    lock = ProjectLockSerializer(read_only=True)

    class Meta:
        model = Project
        fields = [
            "id",
            "title",
            "description",
            "start_date",
            "client_name",
            "client_logo",
            "subproject_count",
            "lock",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields


class ProjectDetailSerializer(serializers.ModelSerializer):
    """Full serializer for project detail / create / update."""

    subprojects = SubProjectSerializer(many=True, read_only=True)
    lock = ProjectLockSerializer(read_only=True)
    created_by = UserSerializer(read_only=True)

    class Meta:
        model = Project
        fields = [
            "id",
            "organization",
            "title",
            "description",
            "start_date",
            # Client
            "client_name",
            "client_logo",
            "client_contact",
            "client_email",
            "client_phone",
            # Graphic
            "primary_color",
            "secondary_color",
            "font_family",
            "watermark_text",
            "watermark_image",
            "watermark_opacity",
            # Header / Footer
            "header_logo_left",
            "header_text_center",
            "header_show_date",
            "footer_text",
            "footer_page_numbering",
            # Template
            "template_name",
            "template_html",
            # Relations
            "subprojects",
            "lock",
            "created_by",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "id",
            "organization",
            "subprojects",
            "lock",
            "created_by",
            "created_at",
            "updated_at",
        ]

    def validate_primary_color(self, value: str) -> str:
        if not value.startswith("#") or len(value) not in (4, 7):
            raise serializers.ValidationError("Must be a valid hex color (e.g. #3b82f6).")
        return value

    def validate_secondary_color(self, value: str) -> str:
        if not value.startswith("#") or len(value) not in (4, 7):
            raise serializers.ValidationError("Must be a valid hex color (e.g. #64748b).")
        return value

    def validate_watermark_opacity(self, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise serializers.ValidationError("Watermark opacity must be between 0.0 and 1.0.")
        return value
