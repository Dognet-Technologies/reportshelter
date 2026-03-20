"""
Management command to create a default admin user on first startup.

Usage:
    python manage.py create_default_admin

The command is idempotent: if an admin user already exists it exits without
making any changes.  The created user is flagged with must_change_password=True
so they are prompted to set a new password on first login.
"""

import secrets
import string

from django.core.management.base import BaseCommand

from apps.accounts.models import Organization, User


class Command(BaseCommand):
    """Create a default admin user if no users exist yet."""

    help = "Create a default admin user for first-time setup"

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--email",
            default="admin@cyberreport.local",
            help="Email address for the default admin (default: admin@cyberreport.local)",
        )
        parser.add_argument(
            "--org-name",
            default="Default Organization",
            help="Name of the default organization (default: Default Organization)",
        )

    def handle(self, *args, **options) -> None:
        email: str = options["email"]
        org_name: str = options["org_name"]

        if User.objects.exists():
            self.stdout.write(
                self.style.WARNING("Users already exist — skipping default admin creation.")
            )
            return

        # Create the default organization
        org, _ = Organization.objects.get_or_create(
            slug="default",
            defaults={"name": org_name},
        )

        # Generate a random temporary password (16 chars, mixed)
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        temp_password = "".join(secrets.choice(alphabet) for _ in range(16))

        user = User.objects.create_user(
            email=email,
            password=temp_password,
            organization=org,
            role=User.Role.ADMIN,
            is_email_verified=True,
            must_change_password=True,
            is_staff=True,
        )

        self.stdout.write(self.style.SUCCESS("Default admin created successfully."))
        self.stdout.write(f"  Email:    {user.email}")
        self.stdout.write(f"  Password: {temp_password}")
        self.stdout.write(
            self.style.WARNING(
                "  IMPORTANT: Change this password immediately after first login!"
            )
        )
