"""
Management command to create a default admin user on first startup.

Usage:
    python manage.py create_default_admin

The command is idempotent: if an admin user already exists it exits without
making any changes.  The created user has credentials admin / admin and is
flagged with must_change_password=True so they must set a new password and
email address on first login.
"""

from django.core.management.base import BaseCommand

from apps.accounts.models import Organization, User
from apps.licensing.models import License

_DEFAULT_EMAIL = "admin@localhost"
_DEFAULT_PASSWORD = "admin"


class Command(BaseCommand):
    """Create a default admin user if no users exist yet."""

    help = "Create a default admin user for first-time setup"

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--org-name",
            default="Default Organization",
            help="Name of the default organization (default: Default Organization)",
        )

    def handle(self, *args, **options) -> None:
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

        user = User.objects.create_user(
            email=_DEFAULT_EMAIL,
            password=_DEFAULT_PASSWORD,
            organization=org,
            role=User.Role.ADMIN,
            is_email_verified=True,
            must_change_password=True,
            is_staff=True,
        )

        # Create a trial license for the new organization
        License.create_trial(org)

        self.stdout.write(self.style.SUCCESS("Default admin created successfully."))
        self.stdout.write(f"  Username: admin  (login with 'admin' or '{user.email}')")
        self.stdout.write(f"  Password: {_DEFAULT_PASSWORD}")
        self.stdout.write(
            self.style.WARNING(
                "  IMPORTANT: You will be prompted to change the password and set your email on first login."
            )
        )
