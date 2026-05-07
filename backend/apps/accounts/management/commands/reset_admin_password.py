"""
Reset the first admin user's password back to 'admin' and force a change on next login.

Usage:
    python manage.py reset_admin_password
    python manage.py reset_admin_password --email user@example.com
"""

from django.core.management.base import BaseCommand

from apps.accounts.models import User

_DEFAULT_PASSWORD = "admin"


class Command(BaseCommand):
    help = "Reset an admin user's password to 'admin' and force change on next login"

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--email",
            default=None,
            help="Email of the user to reset (default: first admin found)",
        )

    def handle(self, *args, **options) -> None:
        email = options["email"]

        if email:
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                self.stderr.write(self.style.ERROR(f"No user found with email: {email}"))
                return
        else:
            user = User.objects.filter(role=User.Role.ADMIN).order_by("date_joined").first()
            if not user:
                self.stderr.write(self.style.ERROR("No admin users found."))
                return

        user.set_password(_DEFAULT_PASSWORD)
        user.must_change_password = True
        user.save(update_fields=["password", "must_change_password"])

        self.stdout.write(self.style.SUCCESS(f"Password reset for: {user.email}"))
        self.stdout.write(f"  New password: {_DEFAULT_PASSWORD}")
        self.stdout.write(self.style.WARNING("  User will be forced to change it on next login."))
