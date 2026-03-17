"""
Serializers for the accounts app.
"""

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from .models import AuditLog, Organization, User


class OrganizationSerializer(serializers.ModelSerializer):
    """Serializer for Organization — read/write for org admins."""

    class Meta:
        model = Organization
        fields = [
            "id",
            "name",
            "slug",
            "address",
            "phone",
            "email",
            "website",
            "vat_number",
            "legal_disclaimer",
            "logo",
            "primary_color",
            "secondary_color",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "slug", "created_at", "updated_at"]


class UserSerializer(serializers.ModelSerializer):
    """Public-safe user representation."""

    full_name = serializers.CharField(read_only=True)
    organization_id = serializers.IntegerField(source="organization.id", read_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "role",
            "organization_id",
            "is_email_verified",
            "date_joined",
            "last_login",
        ]
        read_only_fields = ["id", "email", "organization_id", "is_email_verified", "date_joined", "last_login"]


class RegisterSerializer(serializers.Serializer):
    """User + Organization registration in one step."""

    # Organization fields
    organization_name = serializers.CharField(max_length=255)

    # User fields
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)
    first_name = serializers.CharField(max_length=150, required=False, default="")
    last_name = serializers.CharField(max_length=150, required=False, default="")

    def validate_email(self, value: str) -> str:
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value.lower()

    def validate_password(self, value: str) -> str:
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(list(e.messages)) from e
        return value

    def create(self, validated_data: dict) -> User:
        import uuid

        from django.utils.text import slugify

        org_name = validated_data.pop("organization_name")
        slug = slugify(org_name)
        if Organization.objects.filter(slug=slug).exists():
            slug = f"{slug}-{uuid.uuid4().hex[:6]}"

        organization = Organization.objects.create(name=org_name, slug=slug)

        user = User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            organization=organization,
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
            role=User.Role.ADMIN,
        )
        return user


class LoginSerializer(serializers.Serializer):
    """Email + password login."""

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class PasswordChangeSerializer(serializers.Serializer):
    """Change password for authenticated user."""

    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=12)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs: dict) -> dict:
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        try:
            validate_password(attrs["new_password"])
        except DjangoValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)}) from e
        return attrs


class PasswordResetRequestSerializer(serializers.Serializer):
    """Request a password reset email."""

    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Confirm password reset with token."""

    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, min_length=12)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs: dict) -> dict:
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        try:
            validate_password(attrs["new_password"])
        except DjangoValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)}) from e
        return attrs


class InviteUserSerializer(serializers.Serializer):
    """Invite a user to join the organization."""

    email = serializers.EmailField()
    role = serializers.ChoiceField(choices=User.Role.choices, default=User.Role.MEMBER)
    first_name = serializers.CharField(max_length=150, required=False, default="")
    last_name = serializers.CharField(max_length=150, required=False, default="")


class AuditLogSerializer(serializers.ModelSerializer):
    """Read-only audit log entry."""

    user_email = serializers.CharField(source="user.email", read_only=True, default=None)

    class Meta:
        model = AuditLog
        fields = ["id", "action", "user_email", "detail", "ip_address", "created_at"]
        read_only_fields = fields
